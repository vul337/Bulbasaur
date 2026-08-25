#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FuzzType {
    AFLFuzz,
    LenFuzz,
    DirectCopyFuzz,
    // InferTaint,
    TaintFuzz,
    Trim,
    ExploitFuzz,
    Sync,
    Default
}

pub const FUZZ_TYPE_NUM: usize = FuzzType::Default as usize;


static FUZZ_TYPE_NAME: [&str; FUZZ_TYPE_NUM] = ["AFL", "Len", "Direct", "Taint", "Trim", "Exploit", "Sync"];
pub fn get_fuzz_type_name(i: usize) -> String {
    FUZZ_TYPE_NAME[i].to_string()
}

impl Default for FuzzType {
    fn default() -> Self {
        FuzzType::Default
    }
}

impl FuzzType {
    pub fn index(&self) -> usize {
        *self as usize
    }
}