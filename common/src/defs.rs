// check_dep.rs
pub static DISABLE_CPU_BINDING_VAR: &str = "BULBASAUR_DISABLE_CPU_BINDING";

pub static PERSIST_ENV_VAR: &str = "__AFL_PERSISTENT";
pub static DEFER_ENV_VAR: &str = "__AFL_DEFER_FORKSRV";

pub static PERSIST_SIG: &str = "##SIG_AFL_PERSISTENT##";
pub static DEFER_SIG: &str = "##SIG_AFL_DEFER_FORKSRV##";

// executor.rs
pub static TRACE_SHM_ENV_VAR: &str = "__AFL_SHM_ID"; 
pub static BRANCH_SHM_ENV_VAR: &str = "BRANCH_SHM_ID";
pub static FRONTIER_BRANCH_SHM_VAR: &str = "FRONTIER_SHM_ID";
pub static MAP_SIZE_ENV_VAR: &str = "AFL_MAP_SIZE";
pub static FRONTIER_CMP_TRACE_VAR: &str = "FRONTIER_CMP_TRACE_SHM_ID";

pub static SHM_FUZZ_ENV_VAR: &str = "__AFL_SHM_FUZZ_ID";

pub static LD_LIBRARY_PATH_VAR: &str = "LD_LIBRARY_PATH";
pub static ASAN_OPTIONS_VAR: &str = "ASAN_OPTIONS";
pub static MSAN_OPTIONS_VAR: &str = "MSAN_OPTIONS";
pub static ASAN_OPTIONS_CONTENT: &str =
    "abort_on_error=1:detect_leaks=0:symbolize=0:allocator_may_return_null=1";
pub const MSAN_ERROR_CODE: i32 = 86;
pub static MSAN_OPTIONS_CONTENT: &str =
    "exit_code=86:symbolize=0:abort_on_error=1:allocator_may_return_null=1:msan_track_origins=0";

// depot.rs
pub static CRASHES_DIR: &str = "crashes";
pub static HANGS_DIR: &str = "hangs";
pub static INPUTS_DIR: &str = "queue";

// forksrv.rs
pub static PARAFUZZ_FORKSRV_FD_VAR: &str = "PARAFUZZ_FORKSRV_FD";
pub static READ_ELF_SECTION_DATA_VAR: &str = "READ_ELF_SECTION_DATA";

// command.rs
pub static BULBASAUR_LOG_FILE: &str = "plot_data";
pub static CHART_STAT_FILE: &str = "chart_stat.json";


