use super::{limit::SetLimit, *};
use bulbasaur_common::defs::*;
use crate::branches::MapSizeData;
use libc;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::unistd::{dup2, pipe, close};
use nix::unistd::Pid;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::signal::{SigAction, SigHandler, SaFlags, SigSet, Signal, sigaction, kill};
use nix::sys::wait::waitpid;
use nix::errno::Errno;
use std::os::unix::process::CommandExt;
use libc::{prctl, PR_SET_PDEATHSIG, SIGKILL};

use std::{
    os::fd::{IntoRawFd, FromRawFd, AsFd},
    time::Duration,
    collections::HashMap,
    fs::File,
    io,
    io::prelude::*,
    os::unix::io::RawFd,
    convert::TryInto,
    process::{Command, Stdio},
    thread::sleep,
};

const FS_ERROR_MAP_SIZE: u32 = 1;
const FS_ERROR_MAP_ADDR: u32 = 2;
const FS_ERROR_SHM_OPEN: u32 = 4;
const FS_ERROR_SHMAT: u32 = 8;
const FS_ERROR_MMAP: u32 = 16;
const FS_NEW_ERROR: u32 = 0xeffe0000;
const FS_NEW_OPT_MAPSIZE: u32 = 0x00000001;        // parameter: 32 bit value
const FS_NEW_OPT_SHDMEM_FUZZ: u32 = 0x00000002;    // parameter: none
const FS_NEW_OPT_AUTODICT: u32 = 0x00000800;       // autodictionary data
const FS_OPT_ERROR: u32 = 0xf800008f;

#[derive(Debug)]
pub struct Forksrv {
    forksrv_fd: i32,
    forksrv_pid: i32,
    child_pid: i32,
    uses_asan: bool,
    pub use_shmem_fuzz: bool,
    map_size_data: MapSizeData,
    fsrv_ctl_fd: File,
    fsrv_st_fd: File,
    last_run_timed_out: u32,
    timeout_ms: u64,
    sync_timeout_ms: u64,
    branch_type_raw_data: Option<Vec<u8>>,
    edge_to_pred_branch_raw_data: Option<Vec<u8>>,
}

impl Forksrv {

    pub fn new(
        forksrv_fd: i32,
        target: &(String, Vec<String>),
        envs: &HashMap<String, String>,
        fd: RawFd,
        is_stdin: bool,
        uses_asan: bool,
        time_limit: u64,
        mem_limit: u64,
        read_section_data: bool,
    ) -> Forksrv {
        debug!("forksrv_fd: {:?}", forksrv_fd);
        let mut st_pipe: [RawFd; 2] = [-1, -1];
        let mut ctl_pipe: [RawFd; 2] = [-1, -1];
        let mut use_shmem_fuzz = false;

        let (st_pipe_read, st_pipe_write) = pipe().expect("FATAL: Failed to create status pipe");
        let (ctl_pipe_read, ctl_pipe_write) = pipe().expect("FATAL: Failed to create control pipe");
        st_pipe[0] = st_pipe_read.into_raw_fd();
        st_pipe[1] = st_pipe_write.into_raw_fd();
        ctl_pipe[0] = ctl_pipe_read.into_raw_fd();
        ctl_pipe[1] = ctl_pipe_write.into_raw_fd();


        let mut envs_fk = envs.clone();
        // PARAFUZZ_FORKSRV_FD_VAR contains the pipe fd used to send msg.
        envs_fk.insert(PARAFUZZ_FORKSRV_FD_VAR.to_string(), forksrv_fd.to_string());
        
        // If READ_ELF_SECTION_DATA_VAR is set, the forksrv will write section data (e.g., branch type) to the pipe.
        if read_section_data {
            envs_fk.insert(READ_ELF_SECTION_DATA_VAR.to_string(), "1".to_string());
        }
        let forksrv_pid: i32;
        
        unsafe {
            forksrv_pid = match Command::new(&target.0)
                .args(&target.1)
                .stdin(Stdio::null())
                .envs(&envs_fk)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .pre_exec(move || {

                    // If the parent process terminates, the child will receive SIGKILL.
                    if prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    // Child process will terminate if receive SIGPIPE.
                    let sa = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
                    sigaction(Signal::SIGPIPE, &sa).expect("FATAL: Failed to reset SIGPIPE handler");

                    dup2(ctl_pipe[0], forksrv_fd).expect("FATAL: dup2() failed");
                    dup2(st_pipe[1], forksrv_fd + 1).expect("FATAL: dup2() failed");

                    // Clear FD_CLOEXEC for forksrv_fd
                    let flags_fd1 = fcntl(forksrv_fd, FcntlArg::F_GETFD).expect("FATAL: fcntl failed");
                    let new_flags_fd1 = flags_fd1 & !FdFlag::FD_CLOEXEC.bits();
                    fcntl(forksrv_fd, FcntlArg::F_SETFD(FdFlag::from_bits_truncate(new_flags_fd1)))
                        .expect("FATAL: Failed to clear FD_CLOEXEC for forksrv_fd");

                    // Clear FD_CLOEXEC for forksrv_fd + 1
                    let flags_fd2 = fcntl(forksrv_fd + 1, FcntlArg::F_GETFD).expect("fcntl failed");
                    let new_flags_fd2 = flags_fd2 & !FdFlag::FD_CLOEXEC.bits();
                    fcntl(forksrv_fd + 1, FcntlArg::F_SETFD(FdFlag::from_bits_truncate(new_flags_fd2)))
                        .expect("FATAL: Failed to clear FD_CLOEXEC for forksrv_fd + 1");
                
                    Ok(())
                })
                .mem_limit(mem_limit.clone())
                .setsid()
                .pipe_stdin(fd, is_stdin)
                .spawn()
            {
                Ok(child) => {
                    child.id() as i32
                },
                Err(e) => {
                    error!("FATAL: Failed to spawn child. Reason: {}", e);
                    panic!();
                },
            };
        }

        debug!("[Forksrv] forksrv_pid: {}", forksrv_pid);

        let _ = close(ctl_pipe[0]);
        let _ = close(st_pipe[1]);

        // st_fd: status fd.
        // ctl_fd: control fd.
        let mut fsrv_st_fd = unsafe { File::from_raw_fd(st_pipe[0]) };
        let mut fsrv_ctl_fd = unsafe { File::from_raw_fd(ctl_pipe[1]) };


        let mut status: u32 = Self::read_u32_from_fd(&mut fsrv_st_fd);
        debug!("[Forksrv] Forksrv version: 0x{:08x}", status);
        if (status & FS_NEW_ERROR) == FS_NEW_ERROR {
            Self::report_error_and_exit(status & 0x0000ffff);
        }

        let keep = status;
        status ^= 0xffffffff;
        Self::write_u32_to_fd(&mut fsrv_ctl_fd, status);

        status = Self::read_u32_from_fd(&mut fsrv_st_fd);
        debug!("[Forksrv] Forksrv version: 0x{:08x}", status);

        // Bulbasaur only supports optional mapsize.
        assert!((status & FS_NEW_OPT_MAPSIZE != 0) && (status & FS_NEW_OPT_AUTODICT == 0));

        // Shmem fuzzing mode.
        if (status & FS_NEW_OPT_SHDMEM_FUZZ) != 0 {
            use_shmem_fuzz = true;
        }
        
        // Read mapsize from child.
        let real_map_size = Self::read_u32_from_fd(&mut fsrv_st_fd);

        // Set mapsize to a multiple of 64 for efficient access.
        let mut tmp_map_size = real_map_size;
        if tmp_map_size % 64 != 0 {
            tmp_map_size = ((tmp_map_size + 63) >> 6) << 6;
        }

        // Read branch mapsize from child.
        // Native LLVM PCGuard targets do not emit Bulbasaur's optional branch
        // range and therefore report zero here.  The branch SHM is allocated
        // unconditionally by `Branches`, so retain one sentinel slot for
        // those targets while preserving the real size for instrumented ones.
        let real_branch_map_size = Self::read_u32_from_fd(&mut fsrv_st_fd).max(1);
        let mut tmp_branch_map_size = real_branch_map_size;
        if tmp_branch_map_size % 64 != 0 {
            tmp_branch_map_size = ((tmp_branch_map_size + 63) >> 6) << 6;
        }

        status = Self::read_u32_from_fd(&mut fsrv_st_fd);

        if status != keep {
            error!("Error in forkserver communication (0x{:08x} => 0x{:08x})", keep, status);
            panic!();
        }

        let mut branch_type_raw_data = None;
        let mut edge_to_pred_branch_raw_data = None;

        // Read section data from pipes.
        if read_section_data {
            // Read branch_type.
            branch_type_raw_data = Some(Self::read_from_fd_by_len(&mut fsrv_st_fd));
            // Read edge_to_pred_branch.
            edge_to_pred_branch_raw_data = Some(Self::read_from_fd_by_len(&mut fsrv_st_fd));
        }

        Forksrv {
            forksrv_fd,
            forksrv_pid,
            child_pid: -1,
            uses_asan,
            use_shmem_fuzz,
            map_size_data: MapSizeData::new(real_map_size as usize, tmp_map_size as usize,
                real_branch_map_size as usize, tmp_branch_map_size as usize),
            fsrv_ctl_fd,
            fsrv_st_fd,
            last_run_timed_out: 1,
            timeout_ms: time_limit,
            sync_timeout_ms: 10 * time_limit, // Initial seeds have a longer timeout.
            branch_type_raw_data,
            edge_to_pred_branch_raw_data,
        }
    }

    // Execute one input.
    pub fn run(&mut self, sync_flag: bool) -> StatusType {
        // Notify to fork child.
        Self::write_u32_to_fd(&mut self.fsrv_ctl_fd, self.last_run_timed_out);
        self.last_run_timed_out = 0;

        self.child_pid = Self::read_u32_from_fd(&mut self.fsrv_st_fd) as i32;

        if self.child_pid <= 0 {
        
            if (self.child_pid & FS_OPT_ERROR as i32 != 0) &&
                ((self.child_pid & 0x00ffff00) >> 8) == (FS_ERROR_SHM_OPEN as i32) {
                error!("FATAL: Target reported shared memory access failed (perhaps increase shared memory available).");
                panic!();
            }

            error!("FATAL: Fork server is misbehaving (OOM?)");
            panic!();
        
        }

        let run_timeout = if sync_flag { self.sync_timeout_ms } else { self.timeout_ms };
        let child_status = match Self::read_u32_timed(&mut self.fsrv_st_fd, run_timeout) {
            Ok(value) => value,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                // Handle timeout
                if self.child_pid > 0 {
                    if let Err(e) = kill(Pid::from_raw(self.child_pid), Signal::SIGKILL) {
                        if e == Errno::ESRCH {
                            warn!("Child process {} does not exist, skipping kill.", self.child_pid);
                        } else {
                            error!("Failed to kill child process {}: {}", self.child_pid, e);
                            panic!()
                        }
                    }
                    self.child_pid = -1;
                }
                self.last_run_timed_out = 1;
                Self::read_u32_from_fd(&mut self.fsrv_st_fd)
            }
            Err(e) => {
                error!("Unknown error in read_u32_timed. Reason: {}", e);
                panic!();
            }
        };

        // Timeout
        if self.last_run_timed_out == 1 {
            return StatusType::Timeout;
        }
        // Crash
        if libc::WIFSIGNALED(child_status as i32) || (self.uses_asan && libc::WEXITSTATUS(child_status as i32) == MSAN_ERROR_CODE) {
            return StatusType::Crash;
        }
        // Normal
        StatusType::Normal
    }

    pub fn get_map_size_data(&self) -> MapSizeData {
        self.map_size_data.clone()
    }

    pub fn get_section_raw_data(&self) -> (Vec<u8>, Vec<u8>) {
        let branch_type = self.branch_type_raw_data.as_ref().expect("branch_type_raw_data is None");
        let edge_to_pred = self.edge_to_pred_branch_raw_data.as_ref().expect("edge_to_pred_branch_raw_data is None");

        (branch_type.clone(), edge_to_pred.clone())
    }

    fn report_error_and_exit(error: u32) -> ! {
        match error {
            FS_ERROR_MAP_SIZE => error!("AFL_MAP_SIZE is not set and fuzzing target reports that the \
                required size is very large. Solution: Run the fuzzing target stand-alone with the \
                environment variable AFL_DUMP_MAP_SIZE=1 set the displayed value in the AFL_MAP_SIZE \
                environment variable for afl-fuzz."),
                
            FS_ERROR_MAP_ADDR => error!("The fuzzing target reports that hardcoded map address might be \
                the reason the mmap of the shared memory failed. Solution: recompile the target with \
                either afl-clang-lto and do not set AFL_LLVM_MAP_ADDR or recompile with afl-clang-fast."),
    
            FS_ERROR_SHM_OPEN => error!("The fuzzing target reports that the shm_open() call failed."),
    
            FS_ERROR_SHMAT => error!("The fuzzing target reports that the shmat() call failed."),
    
            FS_ERROR_MMAP => error!("The fuzzing target reports that the mmap() call to the shared \
                memory failed."),
    
            _ => error!("Unknown error code {} from fuzzing target!", error),
        }
        panic!()
    }

    fn read_u32_from_fd(fd: &mut File) -> u32 {
        // Read u32 from the pipe.
        let mut buffer = [0u8; 4];
        fd.read_exact(&mut buffer).unwrap_or_else(|e| {
            error!("FATAL: Failed to read from fd: {}", e);
            panic!();
        });
        u32::from_ne_bytes(buffer)
    }

    fn read_from_fd_by_len(fd: &mut File) -> Vec<u8> {
        // Step 1: Read the first 4 bytes which represent the length
        let mut len_buf = [0u8; 4];
        fd.read_exact(&mut len_buf).unwrap();
        let len = u32::from_ne_bytes(len_buf) as usize;

        // Step 2: Read the data in a loop
        let mut buf = vec![0u8; len];
        let mut offset = 0;

        while offset < len {
            let read_bytes = fd.read(&mut buf[offset..]).unwrap();
            if read_bytes == 0 {
                error!("Pipe closed prematurely");
                panic!();
            }
            offset += read_bytes;
        }

        buf
    }
    
    fn write_u32_to_fd(fd: &mut File, value: u32) {
        let bytes = value.to_ne_bytes();
        fd.write_all(&bytes).unwrap_or_else(|e| {
            error!("FATAL: Failed to write to fd: {}", e);
            panic!();
        });
    }

    fn read_u32_timed(fd: &mut File, timeout_ms: u64) -> io::Result<u32> {
        let mut poll_fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];

        let timeout: PollTimeout = timeout_ms.try_into().expect("Invalid timeout value");

        let poll_result = match poll(&mut poll_fds, timeout) {
            Ok(value) => value,
            Err(e) => {
                error!("poll failed with error: {}", e);
                panic!()
            }
        };
    
        // Oops, occur timeout...
        if poll_result == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Read timed out"));
        }

        let value = Self::read_u32_from_fd(fd);
        Ok(value)
    }
}

impl Drop for Forksrv {
    fn drop(&mut self) {
        debug!("Exit Forksrv");
        // Kill the forksrv and its child process.
        // Note: if this process is killed (e.g., by SIGKILL), the drop function will not be executed.
        
        if self.child_pid > 0 {
            if let Err(e) = kill(Pid::from_raw(self.child_pid), Signal::SIGKILL) {
                if e == Errno::ESRCH {
                    warn!("Child process {} does not exist, skipping kill.", self.child_pid);
                } else {
                    error!("Failed to kill child process {}: {}", self.child_pid, e);
                    panic!()
                }
            }
        }

        if self.forksrv_pid > 0 {
            if let Err(e) = kill(Pid::from_raw(self.forksrv_pid), Signal::SIGKILL) {
                if e == Errno::ESRCH {
                    warn!("Forksrv process {} does not exist, skipping kill.", self.forksrv_pid);
                } else {
                    error!("Failed to kill forksrv process {}: {}", self.forksrv_pid, e);
                    panic!()
                }
            }
            sleep(Duration::from_micros(25));
            let _ = waitpid(Pid::from_raw(self.forksrv_pid), Some(nix::sys::wait::WaitPidFlag::WNOHANG));
        }
    }
}
