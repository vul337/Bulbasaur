use crate::{check_dep::check_binary, tmpfs};
use std::collections::HashMap;
use std::{
    fmt,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

static TMP_DIR: &str = "tmp";
static INPUT_FILE: &str = "cur_input";
const FORKSRV_FD_INIT: i32 = 198;
const FULL_FORKSRV_FD_INIT: i32 = 200;
const TRACE_FORKSRV_FD_INIT: i32 = 202;
const FORKSRV_FD_START: i32 = 208;
const FULL_FORKSRV_FD_START: i32 = 210;
const TRACE_FORKSRV_FD_START: i32 = 212;

impl fmt::Debug for CommandOpt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandOpt")
            .field("id", &self.id)
            .field("main", &self.main)
            .field("full", &self.full)
            .field("trace", &self.trace)
            .field("tmp_dir", &self.tmp_dir)
            .field("out_file", &self.out_file)
            .field("is_stdin", &self.is_stdin)
            .field("mem_limit", &self.mem_limit)
            .field("time_limit", &self.time_limit)
            .field("is_raw", &self.is_raw)
            .field("uses_asan", &self.uses_asan)
            .field("use_shmem_fuzz", &self.use_shmem_fuzz)
            .field("persistent_mode", &self.persistent_mode)
            .field("deferred_mode", &self.deferred_mode)
            .field("forksrv_fd", &self.forksrv_fd)
            .field("full_forksrv_fd", &self.full_forksrv_fd)
            .field("trace_forksrv_fd", &self.trace_forksrv_fd)
            .field("scheduled_mutation", &self.scheduled_mutation)
            .field("havoc_div", &self.havoc_div)
            .field("max_taint_file", &self.max_taint_file)
            .field("edge_to_pred_branch_dict", &"<hidden>")
            .field("branch_boundary", &"<hidden>")
            .field("use_llm", &self.use_llm)
            .finish()
    }
}


#[derive(Clone)]
pub struct CommandOpt {
    pub id: usize,
    pub main: (String, Vec<String>),
    pub full: (String, Vec<String>),
    pub trace: (String, Vec<String>),
    pub tmp_dir: PathBuf,
    pub out_dir: PathBuf,
    pub out_file: String,
    pub is_stdin: bool,
    pub mem_limit: u64,
    pub time_limit: u64,
    pub is_raw: bool,
    pub uses_asan: bool,
    pub use_shmem_fuzz: bool,
    pub persistent_mode: bool,
    pub deferred_mode: bool,
    pub forksrv_fd: i32,
    pub full_forksrv_fd: i32,
    pub trace_forksrv_fd: i32,
    pub scheduled_mutation: bool,
    pub havoc_div: usize,
    pub max_taint_file: usize,
    pub edge_to_pred_branch_dict: HashMap<usize, usize>,
    pub branch_boundary: HashMap<usize, usize>,
    pub use_llm: bool,
}

impl CommandOpt {
    pub fn new(
        pargs: Vec<String>,
        full_target: &str,
        trace_target: &str,
        out_dir: &Path,
        mut mem_limit: u64,
        time_limit: u64,
        scheduled_mutation: bool,
        use_llm: bool,
    ) -> Self {
        let out_dir = PathBuf::from(out_dir);
        let tmp_dir = out_dir.join(TMP_DIR);
        tmpfs::create_tmpfs_dir(&tmp_dir);

        let out_file = tmp_dir.join(INPUT_FILE).to_str().unwrap().to_owned();
        let has_input_arg = pargs.contains(&"@@".to_string());

        let mut tmp_args = pargs.clone();
        let main_bin = tmp_args[0].clone();
        let main_args: Vec<String> = tmp_args.drain(1..).collect();
        let (uses_asan, persistent_mode, deferred_mode) = check_binary(&main_bin);

        if uses_asan && mem_limit != 0 {
            warn!("The program compiled with ASAN, set MEM_LIMIT to 0 (unlimited)");
            mem_limit = 0;
        }

        for bin in [&main_bin].iter() {
            match fs::metadata(bin) {
                Ok(meta) => {
                    assert!(meta.is_file(), "{:?} is not a file", bin);
                    assert!(meta.mode() & 0o100 != 0, "{:?} is not executable", bin);
                },
                Err(_) => panic!("{:?} doesn't exist", bin),
            };
        }

        Self {
            id: 0,
            main: (main_bin, main_args.clone()),
            full: (full_target.to_string(), main_args.clone()),
            trace: (trace_target.to_string(), main_args),
            out_dir,
            tmp_dir,
            out_file,
            is_stdin: !has_input_arg,
            mem_limit,
            time_limit,
            uses_asan,
            use_shmem_fuzz: false,
            persistent_mode,
            deferred_mode,
            is_raw: true,
            forksrv_fd: FORKSRV_FD_INIT,
            full_forksrv_fd: FULL_FORKSRV_FD_INIT,
            trace_forksrv_fd: TRACE_FORKSRV_FD_INIT,
            scheduled_mutation,
            havoc_div: 1,
            max_taint_file: 1,
            edge_to_pred_branch_dict: HashMap::new(),
            branch_boundary: HashMap::new(),
            use_llm,
        }
    }

    // Returns a duplicate of `CommandOpt` that contains all settings for a fuzzing thread.
    pub fn specify(&self, id: usize) -> Self {
        let mut cmd_opt = self.clone();
        let new_file = format!("{}_{}", &cmd_opt.out_file, id);
        for arg in &mut cmd_opt.main.1 {
            if arg == "@@" {
                if self.is_stdin || self.use_shmem_fuzz {
                    error!("@@ is not allowed in arguments when shmem mode or stdin mode is enabled.");
                    panic!();
                }
                *arg = new_file.clone();
            }
        }
        
        cmd_opt.full.1 = cmd_opt.main.1.clone();
        cmd_opt.trace.1 = cmd_opt.main.1.clone();
        cmd_opt.id = id;
        cmd_opt.out_file = new_file.to_owned();
        cmd_opt.is_raw = false;
        cmd_opt.forksrv_fd = FORKSRV_FD_START + id as i32 * 10;
        cmd_opt.full_forksrv_fd = FULL_FORKSRV_FD_START + id as i32 * 10;
        cmd_opt.trace_forksrv_fd = TRACE_FORKSRV_FD_START + id as i32 * 10;
        cmd_opt
    }
}