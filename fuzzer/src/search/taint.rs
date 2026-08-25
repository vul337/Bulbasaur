// Taint-guided fuzzing: uses branch operand values extracted by the trace target
// to drive two complementary strategies:
//   1. len_fuzz    — adjusts input length based on length-comparison hints.
//   2. direct_copy_fuzz — replaces operand bytes in the input to satisfy branch conditions.
//
// For branches that have an associated Agent/custom mutation function, direct_copy_fuzz
// calls the function in an isolated fork process (ForkMutationExecutor) with a 1-second
// wall-clock timeout, falling back to byte-level operand swapping on failure.

use super::*;
use bulbasaur_common::{config, mutate_func::MutateFunc};
use crate::fuzz_type::FuzzType;
use crate::depot::SeedInfo;
use rand::Rng;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};
use std::ptr;
use libc::{
    fork, kill, mmap, shm_open, ftruncate, waitpid, _exit,
    rlimit, setrlimit, RLIMIT_AS, RLIMIT_CPU,
    MAP_SHARED, PROT_READ, PROT_WRITE,
    SIGKILL, WNOHANG, O_CREAT, O_RDWR,
};

// ─── ForkMutationExecutor ────────────────────────────────────────────────────

// Runs a custom mutation function in a forked child process, communicating via
// a POSIX shared-memory segment.  The child is killed if it exceeds the timeout
// or its memory/CPU rlimits.
//
// SHM layout: [0..4) = u32 payload length, [4..4+payload) = payload bytes.
pub struct ForkMutationExecutor {
    shm_fd: RawFd,
    shm_ptr: *mut u8,
    shm_size: usize, // 4 header bytes + max_payload
}

#[derive(Debug)]
pub enum MutationError {
    Timeout,
    WorkerCrashed,
}

impl ForkMutationExecutor {
    pub fn new(max_payload_size: usize) -> Self {
        unsafe {
            let shm_size = max_payload_size + 4;
            let fd = shm_open(b"/mut_shm\0".as_ptr() as *const i8, O_CREAT | O_RDWR, 0o600);
            ftruncate(fd, shm_size as i64);
            let map = mmap(ptr::null_mut(), shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            ForkMutationExecutor { shm_fd: fd, shm_ptr: map as *mut u8, shm_size }
        }
    }

    // Fork a child that applies `func(buf, op1, op2)` and writes the result back via SHM.
    //
    // Return value encodes the mutation function's exit code:
    //   Ok((1, mutated_buf)) — mutation succeeded.
    //   Ok((0, _))           — function chose not to mutate.
    //   Ok((-1, _))          — function reported an error.
    //   Err(Timeout)         — child exceeded `timeout`.
    //   Err(WorkerCrashed)   — child exited abnormally, or input too large.
    pub fn run_mutation(
        &self,
        func: MutateFunc,
        buf: &[u8],
        op1: &[u8],
        op2: &[u8],
        timeout: Duration,
    ) -> Result<(i32, Vec<u8>), MutationError> {
        unsafe {
            let max_payload = self.shm_size - 4;
            if buf.len() > max_payload {
                return Err(MutationError::WorkerCrashed);
            }

            // Write input to SHM.
            let len_u32 = buf.len() as u32;
            ptr::copy_nonoverlapping(&len_u32 as *const u32 as *const u8, self.shm_ptr, 4);
            ptr::copy_nonoverlapping(buf.as_ptr(), self.shm_ptr.add(4), buf.len());

            let pid = fork();

            if pid == 0 {
                // Child: apply rlimits, run mutation, write result back to SHM, then exit.
                let mem_limit = rlimit { rlim_cur: 64 << 20, rlim_max: 64 << 20 };
                setrlimit(RLIMIT_AS, &mem_limit);
                let cpu_limit = rlimit { rlim_cur: 1, rlim_max: 1 };
                setrlimit(RLIMIT_CPU, &cpu_limit);

                let in_len = (*(self.shm_ptr as *const u32) as usize).min(max_payload);
                let mut v = std::slice::from_raw_parts(self.shm_ptr.add(4), in_len).to_vec();

                let mut op1_vec = op1.to_vec();
                let mut op2_vec = op2.to_vec();
                // Randomly swap operands so the function sees both orderings.
                if rand::thread_rng().gen_bool(0.5) {
                    std::mem::swap(&mut op1_vec, &mut op2_vec);
                }

                let code = func(&mut v as *mut Vec<u8>, &op1_vec, &op2_vec);

                let out_len = v.len().min(max_payload) as u32;
                ptr::copy_nonoverlapping(&out_len as *const u32 as *const u8, self.shm_ptr, 4);
                ptr::copy_nonoverlapping(v.as_ptr(), self.shm_ptr.add(4), out_len as usize);

                // Map mutation return code to exit status: -1→2, 0→0, 1→1.
                _exit(match code { 1 => 1, 0 => 0, _ => 2 });
            }

            // Parent: poll child with timeout.
            let start = Instant::now();
            let mut status = 0i32;
            loop {
                let r = waitpid(pid, &mut status, WNOHANG);
                if r == pid {
                    let exit_code = (status >> 8) & 0xff;
                    let code = match exit_code { 1 => 1, 0 => 0, _ => -1 };
                    let new_len = (*(self.shm_ptr as *const u32) as usize).min(max_payload);
                    let out = std::slice::from_raw_parts(self.shm_ptr.add(4), new_len).to_vec();
                    return Ok((code, out));
                }
                if start.elapsed() > timeout {
                    kill(pid, SIGKILL);
                    waitpid(pid, &mut status, 0);
                    return Err(MutationError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

// ─── TaintFuzz ───────────────────────────────────────────────────────────────

pub struct TaintFuzz {
    havoc_div: usize,
    run_ratio: usize,
    fork_exec: ForkMutationExecutor,
    use_llm: bool,
}

impl TaintFuzz {
    pub fn new(havoc_div: usize, use_llm: bool) -> Self {
        Self {
            havoc_div,
            run_ratio: 0,
            fork_exec: ForkMutationExecutor::new(1024 * 1024), // 1 MB SHM
            use_llm,
        }
    }

    pub fn run<T: Rng>(&mut self, handler: &mut SearchHandler, rng: &mut T) {
        self.run_ratio = handler.calculate_score();

        // Phase 1: run the trace target to collect branch operand data.
        handler.executor.local_stats.register(FuzzType::TaintFuzz);
        let mut tmp_buf = handler.buf.clone();
        handler.execute_trace_and_load(&tmp_buf);
        handler.executor.update_log();

        // Phase 2: try resizing the input based on length comparison hints.
        handler.executor.local_stats.register(FuzzType::LenFuzz);
        self.len_fuzz(handler, &mut tmp_buf, rng);
        handler.executor.update_log();

        // Phase 3: replace operand bytes to push branch conditions closer to satisfied.
        handler.executor.local_stats.register(FuzzType::DirectCopyFuzz);
        self.direct_copy_fuzz(handler, &mut tmp_buf, rng);
        handler.executor.update_log();
    }

    // Tries trimming or extending the input to the lengths suggested by the trace.
    // For each candidate length, runs the target once and restores the buffer afterwards.
    pub fn len_fuzz<T: Rng>(&mut self, handler: &mut SearchHandler, tmp_buf: &mut Vec<u8>, rng: &mut T) {
        assert_eq!(tmp_buf.len(), handler.buf.len());
        let seed_len = tmp_buf.len();

        for len in handler.len_vec.clone() {
            if len == 0 {
                continue;
            }
            if len < seed_len {
                tmp_buf.resize(len, 0);
                handler.execute(tmp_buf, SeedInfo::default());
                tmp_buf.extend_from_slice(&handler.buf[len..]);
            } else if len > seed_len {
                assert!(len <= seed_len * 2 && len <= config::MAX_INPUT_LEN);
                let mut append = vec![0u8; len - seed_len];
                rng.fill_bytes(&mut append);
                tmp_buf.extend_from_slice(&append);
                handler.execute(tmp_buf, SeedInfo::default());
                tmp_buf.resize(seed_len, 0);
            }
        }

        #[cfg(debug_assertions)]
        {
            assert_eq!(tmp_buf.len(), handler.buf.len());
            assert!(tmp_buf.iter().zip(handler.buf.iter()).all(|(a, b)| a == b));
        }
    }

    // For each branch operand pair collected by the trace, randomly selects a mutation
    // strategy (Agent mutation function or byte-level operand swap) and executes the result.
    pub fn direct_copy_fuzz<T: Rng>(&mut self, handler: &mut SearchHandler, input_buf: &mut Vec<u8>, rng: &mut T) {
        let max_cmp = (config::MAX_DIRECT_COPY_TIMES * self.run_ratio / self.havoc_div) >> 8;
        if max_cmp == 0 || handler.cmp_data_in_direct_copy.is_empty() {
            return;
        }

        for _ in 0..max_cmp {
            let max_stacking = 1 << (1 + rng.gen_range(0..config::HAVOC_STACK_POW2));
            let mut tmp_buf = input_buf.clone();
            let mut mutated = false;

            for _ in 0..max_stacking {
                let i = rng.gen_range(0..handler.cmp_data_in_direct_copy.len());
                let cmp_data = handler.cmp_data_in_direct_copy[i].clone();
                let branch_id = handler.index_to_branch_dict[i];

                let success = if self.use_llm && tmp_buf.len() <= config::MAX_INPUT_LEN && rng.gen_bool(0.5) {
                    self.try_mutation_function(handler, &mut tmp_buf, &cmp_data.0, &cmp_data.1, branch_id, rng)
                } else {
                    self.match_and_replace_input(handler, &mut tmp_buf, &cmp_data.0, &cmp_data.1, rng)
                };

                if success {
                    mutated = true;
                }
            }

            if mutated {
                handler.execute(&tmp_buf, SeedInfo::default());
            }
        }
    }

    // Looks up the custom mutation function for `branch_id` and runs it in a forked child.
    // Falls back to `match_and_replace_input` if no function is registered or on error.
    fn try_mutation_function<T: Rng>(
        &mut self,
        handler: &mut SearchHandler,
        tmp_buf: &mut Vec<u8>,
        op1: &Vec<u8>,
        op2: &Vec<u8>,
        branch_id: usize,
        rng: &mut T,
    ) -> bool {
        let global = &handler.executor.branches.global;
        let chunk_idx = global.branch_chunk_of(branch_id);
        let local_idx = branch_id - global.branch_start_pos[chunk_idx];

        let func_ptr = match global.branch_mutate_funcs[chunk_idx].read() {
            Ok(guard) => guard[local_idx].mutate_func,
            Err(_) => {
                log::warn!("Failed to acquire read lock for branch {} (chunk {}, local {})", branch_id, chunk_idx, local_idx);
                return false;
            }
        };

        let func_ptr = match func_ptr {
            Some(f) => f,
            // No function registered — fall back to byte-level swap.
            None => return self.match_and_replace_input(handler, tmp_buf, op1, op2, rng),
        };

        // Disable the function on any failure to avoid repeated overhead.
        let disable = |global: &crate::branches::GlobalBranches| {
            if let Ok(mut guard) = global.branch_mutate_funcs[chunk_idx].write() {
                guard[local_idx].mutate_func = None;
            }
        };

        match self.fork_exec.run_mutation(func_ptr, tmp_buf, op1, op2, Duration::from_secs(1)) {
            Ok((1, mutated)) => {
                *tmp_buf = mutated;
                log::info!("Mutation succeeded for branch {}", branch_id);
                true
            }
            Ok((0, _)) => {
                log::debug!("Mutation returned 0 for branch {} (no change applied)", branch_id);
                false
            }
            Ok(_) => {
                log::warn!("Mutation returned unexpected value for branch {} — disabling", branch_id);
                disable(global);
                false
            }
            Err(MutationError::Timeout) => {
                log::warn!("Mutation timeout at branch {} — disabling", branch_id);
                disable(global);
                false
            }
            Err(MutationError::WorkerCrashed) => {
                log::error!("Mutation worker crashed for branch {} — disabling", branch_id);
                disable(global);
                false
            }
        }
    }

    // Scans `tmp_buf` for occurrences of `op1_substr` or `op2_substr` (and their
    // byte-reversed versions) starting from a random position, replacing the first
    // match with the opposite operand.
    fn match_and_replace_input<T: Rng>(
        &mut self,
        _handler: &mut SearchHandler,
        tmp_buf: &mut Vec<u8>,
        op1_substr: &Vec<u8>,
        op2_substr: &Vec<u8>,
        rng: &mut T,
    ) -> bool {
        let max_len = op1_substr.len().max(op2_substr.len());
        if tmp_buf.len() < max_len {
            return false;
        }

        let rev_op1: Vec<u8> = op1_substr.iter().rev().cloned().collect();
        let rev_op2: Vec<u8> = op2_substr.iter().rev().cloned().collect();

        let mut pos = rng.gen_range(0..tmp_buf.len() - max_len + 1);
        while pos + max_len <= tmp_buf.len() {
            if tmp_buf[pos..pos + op1_substr.len()] == op1_substr[..] {
                tmp_buf.splice(pos..pos + op1_substr.len(), op2_substr.iter().cloned());
                return true;
            } else if tmp_buf[pos..pos + op2_substr.len()] == op2_substr[..] {
                tmp_buf.splice(pos..pos + op2_substr.len(), op1_substr.iter().cloned());
                return true;
            } else if tmp_buf[pos..pos + op1_substr.len()] == rev_op1[..] {
                tmp_buf.splice(pos..pos + op1_substr.len(), rev_op2.iter().cloned());
                return true;
            } else if tmp_buf[pos..pos + op2_substr.len()] == rev_op2[..] {
                tmp_buf.splice(pos..pos + op2_substr.len(), rev_op1.iter().cloned());
                return true;
            }
            pos += 1;
        }

        false
    }
}
