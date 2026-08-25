use super::*;

use crate::{
    branches::{self, MapSizeData}, command,
    depot::{self, SeedInfo}, stats,
};
use bulbasaur_common::{config, defs, shm::SHM};

use std::{
    collections::HashMap,
    sync::{
        atomic::{compiler_fence, Ordering},
        Arc, RwLock,
    },
    mem::drop,
    time,
};


/// The `Executor` is responsible for executing inputs and 
/// contains all global components (e.g., the depot and branches) 
/// that require synchronization.
pub struct Executor {
    pub cmd: command::CommandOpt,       // All settings needed by executor.
    pub branches: branches::Branches,   // Contains branches and edges shared memory.
    envs: HashMap<String, String>,      // The environment variables of fast target.
    full_envs: HashMap<String, String>, // The environment variables of full target.
    trace_envs: HashMap<String, String>,// The environment variables of trace target.
    forksrv: Option<Forksrv>,           // The forksrv of fast target.
    full_forksrv: Option<Forksrv>,      // The forksrv of full target.
    trace_forksrv: Option<Forksrv>,     // The forksrv of trace target.
    pub depot: Arc<depot::Depot>,       // depot contains seeds and decides the next seed to fuzz.
    fd: PipeFd,                         // input fd.
    tmout_cnt: usize,                   // Number of consecutive timeout testcases. (If too many timeouts occur, this seed will be skipped.)
    pub has_new_path: bool,             // 
    pub has_new_edge: bool,             //
    pub has_higher_match: bool,         //
    pub global_stats: Arc<RwLock<stats::ChartStats>>,   // Global stats
    pub local_stats: stats::LocalStats,                 // Local stats
    shmem_fuzz_map: Option<SHM<u8> >,                   // Shared memory used in shmem fuzz mode to deliver testcases to the target program.
}

impl Executor {
    // Builds the common env vars shared by all three target processes:
    // ASAN/MSAN sanitizer options, and optionally the SHM fuzz input ID.
    fn base_envs(shmem_fuzz_id: Option<String>) -> HashMap<String, String> {
        let mut envs = HashMap::new();
        envs.insert(defs::ASAN_OPTIONS_VAR.to_string(), defs::ASAN_OPTIONS_CONTENT.to_string());
        envs.insert(defs::MSAN_OPTIONS_VAR.to_string(), defs::MSAN_OPTIONS_CONTENT.to_string());
        if let Some(id) = shmem_fuzz_id {
            envs.insert(defs::SHM_FUZZ_ENV_VAR.to_string(), id);
        }
        envs
    }

    pub fn new(
        cmd: command::CommandOpt,
        global_branches: Arc<branches::GlobalBranches>,
        depot: Arc<depot::Depot>,
        global_stats: Arc<RwLock<stats::ChartStats>>,
    ) -> Self {
        // Bulbasaur runs three instrumented variants of the same target in lock-step:
        //   fast  — pruned edge bitmap (AFL++ style); used on every input execution.
        //   full  — unpruned edge + branch bitmap; invoked only when a new edge is found.
        //   trace — branch operand recorder; invoked by TaintFuzz to collect cmp parameters.
        let branches = branches::Branches::new(global_branches, depot.clone());

        let shmem_fuzz_map = if cmd.use_shmem_fuzz {
            Some(SHM::<u8>::new(config::MAX_INPUT_LEN + 4))
        } else {
            None
        };
        let shmem_id = shmem_fuzz_map.as_ref().map(|m| m.get_id().to_string());

        // Fast target: edge coverage bitmap + frontier branch match values.
        let mut envs = Self::base_envs(shmem_id.clone());
        envs.insert(defs::TRACE_SHM_ENV_VAR.to_string(),          branches.get_trace_id().to_string());
        envs.insert(defs::FRONTIER_BRANCH_SHM_VAR.to_string(),    branches.get_frontier_branch_id().to_string());
        envs.insert(defs::MAP_SIZE_ENV_VAR.to_string(),            branches.get_map_size().to_string());

        let fd = pipe_fd::PipeFd::new(&cmd.out_file);
        let forksrv = forksrv::Forksrv::new(
            cmd.forksrv_fd,
            &cmd.main,
            &envs,
            fd.as_raw_fd(),
            cmd.is_stdin,
            cmd.uses_asan,
            cmd.time_limit,
            cmd.mem_limit,
            false,
        );

        // Full target: complete edge bitmap with no dominator pruning.
        // Uses 10× the fast timeout because NoPrune instrumentation runs more code.
        let mut full_envs = Self::base_envs(shmem_id.clone());
        full_envs.insert(defs::TRACE_SHM_ENV_VAR.to_string(), branches.get_full_trace_id().to_string());
        full_envs.insert(defs::MAP_SIZE_ENV_VAR.to_string(),  branches.get_full_map_size().to_string());

        let full_forksrv = forksrv::Forksrv::new(
            cmd.full_forksrv_fd,
            &cmd.full,
            &full_envs,
            fd.as_raw_fd(),
            cmd.is_stdin,
            cmd.uses_asan,
            10 * cmd.time_limit,
            cmd.mem_limit,
            false,
        );

        // Trace target: records raw branch operand values into cmp_trace_map.
        // No memory limit — the trace SHM is intentionally larger than normal.
        let mut trace_envs = Self::base_envs(shmem_id.clone());
        trace_envs.insert(defs::FRONTIER_CMP_TRACE_VAR.to_string(), branches.get_cmp_trace_id().to_string());
        trace_envs.insert(defs::TRACE_SHM_ENV_VAR.to_string(),       branches.get_taint_trace_id().to_string());
        trace_envs.insert(defs::MAP_SIZE_ENV_VAR.to_string(),         branches.get_map_size().to_string());

        let trace_forksrv = forksrv::Forksrv::new(
            cmd.trace_forksrv_fd,
            &cmd.trace,
            &trace_envs,
            fd.as_raw_fd(),
            cmd.is_stdin,
            cmd.uses_asan,
            10 * cmd.time_limit,
            0, // No memory limit for trace target (large SHM).
            false,
        );

        if cmd.use_shmem_fuzz {
            assert!(!cmd.is_stdin && forksrv.use_shmem_fuzz && 
                    full_forksrv.use_shmem_fuzz && trace_forksrv.use_shmem_fuzz);
        }

        Self {
            cmd,
            branches,
            envs,
            full_envs,
            trace_envs,
            forksrv: Some(forksrv),
            full_forksrv: Some(full_forksrv),
            trace_forksrv: Some(trace_forksrv),
            depot,
            fd,
            tmout_cnt: 0,
            has_new_path: false,
            has_new_edge: false,
            has_higher_match: false,
            global_stats,
            local_stats: Default::default(),
            shmem_fuzz_map,
        }
    }

    pub fn rebind_forksrv(&mut self) {
        {
            // delete the old forksrv
            self.forksrv = None;
            self.full_forksrv = None;
            self.trace_forksrv = None;
        }
        
        let forksrv = forksrv::Forksrv::new(
            self.cmd.forksrv_fd,
            &self.cmd.main,
            &self.envs,
            self.fd.as_raw_fd(),
            self.cmd.is_stdin,
            self.cmd.uses_asan,
            self.cmd.time_limit,
            self.cmd.mem_limit,
            false,
        );
        self.forksrv = Some(forksrv);

        let full_forksrv = forksrv::Forksrv::new(
            self.cmd.full_forksrv_fd,
            &self.cmd.full,
            &self.full_envs,
            self.fd.as_raw_fd(),
            self.cmd.is_stdin,
            self.cmd.uses_asan,
            self.cmd.time_limit * 10,
            self.cmd.mem_limit,
            false,
        );
        self.full_forksrv = Some(full_forksrv);

        let trace_forksrv = forksrv::Forksrv::new(
            self.cmd.trace_forksrv_fd,
            &self.cmd.trace,
            &self.trace_envs,
            self.fd.as_raw_fd(),
            self.cmd.is_stdin,
            self.cmd.uses_asan,
            self.cmd.time_limit * 20,
            self.cmd.mem_limit,
            false,
        );
        self.trace_forksrv = Some(trace_forksrv);
    }

    // // Check if the input has new found. If yes, update covered branches and insert the input into the depot.
    fn do_if_has_new(&mut self, buf: &Vec<u8>, status: StatusType, seed_info: SeedInfo, sync_flag: bool) {
        /* First, we check if the buf has new edges. */ 
        let (write_flag, mut path, mut edge_to_write) = self.branches.has_new_edge(status, seed_info);

        /* If it has new edges, calibrate it. */  
        if write_flag && status == StatusType::Normal {
            // Calibrate case.
            let mut cal_times = config::CAL_TIME;
            let mut cal_iter = 0;

            while cal_iter < cal_times {
                // Use a longer timeout during calibration to avoid test cases that are prone to timing out
                let now_status = self.run_inner(&mut SeedInfo::default(), true);
                if now_status != status {
                    // That's too bad.
                    error!("The testcase has two different execution status, skip it.");
                    return
                }

                let variable = self.branches.calibrate_edge(&mut path, &mut edge_to_write, false);
                if variable {
                    warn!("The testcase is variable, we will skip all variable edges.");
                    cal_times = config::LONG_CAL_TIME;
                }
                cal_iter += 1;
            }
        }

        /* Second, check if the buf has higher match value. */
        let (has_new_path, has_new_edge, edge_num, has_higher_match) = self.branches.update_edges_and_branches(status, buf, &mut self.local_stats, write_flag, path, edge_to_write, sync_flag);

        self.has_new_path = has_new_path;
        self.has_new_edge = has_new_edge;
        self.has_higher_match = has_higher_match;

        // Make sure all initial seeds inserted into depot.
        if sync_flag {
            if status != StatusType::Normal {
                return
            }
            // assert!(status == StatusType::Normal, 
            //         "Sync execution encountered an abnormal status: {:?}. Please check it...", status);

            self.branches.insert_new_seed(status, buf)
        }

        /* Third, if input has new edges, we update covered branch according to the covered edges of full target. */
        if status == StatusType::Normal {
            self.local_stats.avg_edge_num.update(edge_num as f32);

            if has_new_edge {
                // If has new edge, we will run full target to get full edges and update branch map.
                self.run_full(sync_flag);
                let (write_flag, mut path, mut edge_to_write) = self.branches.has_new_full_edge();

                // Calibrate case.
                let mut cal_times = config::CAL_TIME;
                let mut cal_iter = 0;
                while cal_iter < cal_times {
                    // Use a longer timeout during calibration to avoid test cases that are prone to timing out
                    let full_status = self.run_full(true);
                    if full_status != status {
                        // That's too bad
                        error!("The testcase has two different execution status, skip it.");
                        return
                    }

                    let variable = self.branches.calibrate_edge(&mut path, &mut edge_to_write, true);
                    if variable {
                        warn!("The testcase is variable, we will skip all variable edges.");
                        cal_times = config::LONG_CAL_TIME;
                    }
                    cal_iter += 1;
                };

                let num_new_branches = self.branches.update_branch_boundary(write_flag, path, edge_to_write);
                self.local_stats.num_branches.inc(num_new_branches);
            }
        }

        // TODO: check unlimited timeout or crash.
    }

    // Run mutated input and check if it has new founds.
    pub fn run(&mut self, buf: &Vec<u8>, mut seed_info: SeedInfo) -> StatusType {
        self.run_init();

        seed_info.len = buf.len();

        self.write_test(buf);
        // Record seed info when execute.
        let status = self.run_inner(&mut seed_info, false);
        self.do_if_has_new(buf, status, seed_info, false);
        // If too many timtout cases, return skip.
        self.check_timeout(status)
    }

    // Run initial seeds.
    pub fn run_sync(&mut self, buf: &Vec<u8>, mut seed_info: SeedInfo) -> (bool, usize) {
        self.run_init();

        seed_info.len = buf.len();

        self.write_test(buf);
        // record seed info when execute.
        let status = self.run_inner(&mut seed_info, true);
        let exec_time_us = seed_info.exec_time_us;
        self.do_if_has_new(buf, status, seed_info, true);
        // Get the exec_time and calculate automatic timeout next...
        (status == StatusType::Normal, exec_time_us)
    }

    // Execute trace target to get branches parameters.
    pub fn trace_testcase(&mut self, buf: &Vec<u8>) -> StatusType {
        self.run_init();

        self.write_test(buf);
        self.run_trace(false)
    }

    // Prepare for execution.
    fn run_init(&mut self) {
        self.has_new_path = false;
        self.has_new_edge = false;
        self.has_higher_match = false;
        self.local_stats.num_exec.count();
    }

    // Check if consecutive timeouts occurred.
    fn check_timeout(&mut self, status: StatusType) -> StatusType {
        let mut ret_status = status;
        if ret_status == StatusType::Error {
            self.rebind_forksrv();
            ret_status = StatusType::Timeout;
        }

        if ret_status == StatusType::Timeout {
            self.tmout_cnt = self.tmout_cnt + 1;
            if self.tmout_cnt >= config::TMOUT_SKIP {
                ret_status = StatusType::Skip;
                self.tmout_cnt = 0;
            }
        } else {
            self.tmout_cnt = 0;
        };

        ret_status
    }

    // Function to execute the fast target program.
    fn run_inner(&mut self, seed_info: &mut SeedInfo, sync_flag: bool) -> StatusType {
        if self.cmd.is_stdin {
            self.fd.rewind();
        }
        self.branches.clear_frontier_branch();
        self.branches.clear_trace();

        // Count exec time.
        let t_start = time::Instant::now();
        compiler_fence(Ordering::SeqCst);
        let ret_status = if let Some(ref mut fs) = self.forksrv {
            fs.run(sync_flag)
        } else {
            error!("forksrv doesn't exist.");
            panic!()
        };
        compiler_fence(Ordering::SeqCst);

        let used_t = t_start.elapsed();
        // u32 would overflow for executions > ~4s; use u64 throughout
        let used_us = used_t.as_secs() * 1_000_000 + used_t.subsec_nanos() as u64 / 1_000;
        self.local_stats.avg_exec_time.update(used_us as f32);
        seed_info.exec_time_us = used_us as usize;

        ret_status
    }

    // Function to execute the full target program.
    fn run_full(&mut self, sync_flag: bool) -> StatusType {
        // Testcase has already been written.
        if self.cmd.is_stdin {
            self.fd.rewind();
        }
        self.branches.clear_full_trace();

        compiler_fence(Ordering::SeqCst);
        let ret_status = if let Some(ref mut fs) = self.full_forksrv {
            fs.run(sync_flag)
        } else {
            error!("full_forksrv doesn't exist.");
            panic!()
        };
        compiler_fence(Ordering::SeqCst);

        ret_status
    }

    // Function to execute the trace target program.
    fn run_trace(&mut self, sync_flag: bool) -> StatusType {
        // Testcase has already been written.
        if self.cmd.is_stdin {
            self.fd.rewind();
        }
        self.branches.clear_taint_trace();
        self.branches.clear_cmp_trace();

        compiler_fence(Ordering::SeqCst);
        let ret_status = if let Some(ref mut fs) = self.trace_forksrv {
            fs.run(sync_flag)
        } else {
            error!("trace_forksrv doesn't exist.");
            panic!()
        };
        compiler_fence(Ordering::SeqCst);

        ret_status
    }

    pub fn random_input_buf(&self) -> Vec<u8> {
        let id = self.depot.next_random();
        self.depot.get_input_buf(id)
    }

    pub fn random_splice_input_buf(&self, now_id: usize) -> Vec<u8> {
        let splice_id;
        loop {
            let id = self.depot.next_random();
            if id != now_id {
                splice_id = id;
                break;
            }
        }
        self.depot.get_input_buf(splice_id)
    }

    // Write the input buffer. Currently supports three modes: file, stdin, and shared memory.
    fn write_test(&mut self, buf: &Vec<u8>) {

        if self.cmd.use_shmem_fuzz {

            let mut len = buf.len();
            if len > config::MAX_INPUT_LEN {
                warn!("The length of input exceeds MAX_INPUT_LEN, we will cut it.");
                len = config::MAX_INPUT_LEN;
            }
            let len_bytes = (len as u32).to_ne_bytes();

            // write len
            self.shmem_fuzz_map.as_mut().unwrap()[0..4].copy_from_slice(&len_bytes);
            // write buf
            self.shmem_fuzz_map.as_mut().unwrap()[4..4 + len].copy_from_slice(&buf[0..len]);

        } else {

            self.fd.write_buf(buf);
            if self.cmd.is_stdin {
                self.fd.rewind();
            }

        }
    }
        
    pub fn update_log(&mut self) {
        self.global_stats
            .write()
            .unwrap()
            .sync_from_local(&mut self.local_stats);

        self.tmout_cnt = 0;
    }

    // Create temporary forksrvs and retrieve crucial data (e.g., map size, input mode, and branch types) via pipes.
    pub fn get_crucial_data_from_binary(cmd: & command::CommandOpt) -> (MapSizeData, MapSizeData, MapSizeData, 
                                                                        bool, Vec<u8>, Vec<u8>, Vec<u8>) {

        let branches = branches::TmpBranches::new();
        let tmp_shmem_fuzz = SHM::<u8>::new(config::MAX_INPUT_LEN + 4);

        let mut envs = Self::base_envs(Some(tmp_shmem_fuzz.get_id().to_string()));
        envs.insert(defs::TRACE_SHM_ENV_VAR.to_string(),       branches.get_trace_id().to_string());
        envs.insert(defs::FRONTIER_BRANCH_SHM_VAR.to_string(), branches.get_frontier_branch_id().to_string());
        envs.insert(defs::MAP_SIZE_ENV_VAR.to_string(),        branches.get_map_size().to_string());
        
        let fd = pipe_fd::PipeFd::new(&cmd.out_file);
        let forksrv = forksrv::Forksrv::new(
            cmd.forksrv_fd,
            &cmd.main,
            &envs,
            fd.as_raw_fd(),
            cmd.is_stdin,
            cmd.uses_asan,
            cmd.time_limit,
            cmd.mem_limit,
            true,
        );

        // Retrieve map size and branch type via pipes.
        let fast_map_size_data = forksrv.get_map_size_data();
        let (_fast_branch_type_raw_data, _fast_edge_to_pred_branch_raw_data) = forksrv.get_section_raw_data();
        // FAST is allowed to carry the same optional branch metadata as FULL.
        // The fuzzer uses FULL as the canonical source below, but older code
        // incorrectly asserted that FAST's sections had to be empty. Custom
        // Bulbasaur FAST instrumentation emits these sections, so just ignore
        // the duplicate data rather than rejecting an otherwise valid target.

        // Check if shared memory fuzzing mode is enabled.
        let use_shmem_fuzz = forksrv.use_shmem_fuzz;
        drop(forksrv);

        let full_forksrv = forksrv::Forksrv::new(
            cmd.full_forksrv_fd,
            &cmd.full,
            &envs,
            fd.as_raw_fd(),
            cmd.is_stdin,
            cmd.uses_asan,
            cmd.time_limit,
            cmd.mem_limit,
            true,
        );
        let full_map_size_data = full_forksrv.get_map_size_data();
        let (full_branch_type_raw_data, full_edge_to_pred_branch_raw_data) = full_forksrv.get_section_raw_data();
        // fast forksrv, full forksrv and trace forksrv must have same setting for shmem fuzz.
        assert!(use_shmem_fuzz == full_forksrv.use_shmem_fuzz);

        let trace_forksrv = forksrv::Forksrv::new(
            cmd.trace_forksrv_fd,
            &cmd.trace,
            &envs,
            fd.as_raw_fd(),
            cmd.is_stdin,
            cmd.uses_asan,
            cmd.time_limit,
            0, // It's better not to set memory limit for trace target since it requires larger shared memory.
            true,
        );
        let trace_map_size_data = trace_forksrv.get_map_size_data();
        let (trace_branch_type_raw_data, _trace_edge_to_pred_branch_raw_data) = trace_forksrv.get_section_raw_data();
        // TRACE may also emit the optional edge-to-branch table.  It is not
        // consumed by the trace executor (FULL is canonical), so accept and
        // ignore the duplicate section just like FAST above.
        assert!(use_shmem_fuzz == trace_forksrv.use_shmem_fuzz);

        // Note: all forksrvs will be dropped when the function ends.

        (fast_map_size_data, full_map_size_data, trace_map_size_data, use_shmem_fuzz,
            full_branch_type_raw_data, full_edge_to_pred_branch_raw_data, trace_branch_type_raw_data)
    }
}
