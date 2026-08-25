use crate::config::UNIT_MAX_TRACE_CNT;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CmpTraceUnit {
    pub len: u32,
    pub match_num: u16,
    pub op1: u64,
    pub op2: u64,
    pub unused: [u8; 48],
}

impl Default for CmpTraceUnit {
    fn default() -> Self {
        Self {
            len: 0,
            match_num: 0,
            op1: 0,
            op2: 0,
            unused: [0u8; 48],
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CmpTrace {
    pub size: u16,
    pub units: [CmpTraceUnit; UNIT_MAX_TRACE_CNT]
}

impl Default for CmpTrace {
    fn default() -> Self {
        Self { 
            size: 0,
            units: [CmpTraceUnit::default(); UNIT_MAX_TRACE_CNT],
        }
    }
}


#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct StrcmpTraceUnit {
    pub len1: u8,
    pub len2: u8,
    pub len3: u8,
    pub occu: u8,
    pub match_num: u16,
    pub op1: [u8; 32],
    pub op2: [u8; 32],
}

impl Default for StrcmpTraceUnit {
    fn default() -> Self {
        Self {
            len1: 0,
            len2: 0,
            len3: 0,
            occu: 0,
            match_num: 0,
            op1: [0u8; 32],
            op2: [0u8; 32],
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct StrcmpTrace {
    pub size: u16,
    pub units: [StrcmpTraceUnit; UNIT_MAX_TRACE_CNT]
}

impl Default for StrcmpTrace {
    fn default() -> Self {
        Self { 
            size: 0,
            units: [StrcmpTraceUnit::default(); UNIT_MAX_TRACE_CNT],
        }
    }
}