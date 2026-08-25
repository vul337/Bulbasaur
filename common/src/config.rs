
// The maximum length of inputs.
pub const MAX_INPUT_LEN: usize = 1024 * 1024;

// The maximum number of different contexts for branches and edges.
pub const BRANCH_CONTEXT_CNT: usize = 8;

// trace_data.rs
pub const UNIT_MAX_TRACE_CNT: usize = 32;

// branch.rs
pub const TMP_MAP_SIZE: usize = 1 << 24;    // Huge, this is a temporary value.

// executor.rs
pub const CAL_TIME: usize = 3;
pub const LONG_CAL_TIME: usize = 6;
pub const TMOUT_SKIP: usize = 3;
pub const TIME_LIMIT: u64 = 1000;  // ms
pub const MEM_LIMIT: u64 = 200; // MB

// trim.rs
pub const TRIM_MIN_BYTES: usize = 4;
pub const TRIM_START_STEPS: usize = 16;
pub const TRIM_END_STEPS: usize = 1024;

// ************ Mutation ****************
// handler.rs
pub const NEW_EDGE_BONUS: f64 = 2.0;
pub const NEW_PATH_BONUS: f64 = 1.2;
pub const GREATER_DIST_BONUS: f64 = 1.2;

// afl.rs
pub const POSITION_NUM: usize = 10;   // The number of position ranges used for scheduling.
pub const HAVOC_STACK_POW2: usize = 4;
pub const HAVOC_MAX_MULT:usize = 64;

/// havoc stage
pub const MAX_HAVOC_TIMES: usize = 256; 

/// splice stage
pub const MAX_SPLICE_TIMES: usize = 32; 
pub const MAX_SPLICE_CYCLES: usize = 8;

pub const ARITH_MAX: u32 = 35;
pub const HAVOC_BLK_SMALL: u32 = 32;
pub const HAVOC_BLK_MEDIUM: u32 = 128;
pub const HAVOC_BLK_LARGE: u32 = 1500;
pub const HAVOC_BLK_XL: u32 = 32768;

// taint.rs
pub const MAX_DIRECT_COPY_TIMES: usize = 128; // direct copy havoc stage
pub const MAX_TAINT_TIMES: usize = 128; // taint stage

// depot.rs
pub const TS_THRESHOLD: usize = 1000;
pub const TS_DECAY_FACTOR: f64 = 0.99;

// llm_loop.rs
pub const MAX_RETRY_COUNT: usize = 2;
pub const TIME_INTERVAL: usize = 6 * 60 * 60; // 6 hours (in seconds)
pub const CHECK_INTERVAL: usize = 60 * 60; // check every hour (in seconds)
