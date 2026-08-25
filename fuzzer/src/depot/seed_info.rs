use std::hash::{Hash, Hasher};
#[derive(Clone, Copy, Debug)]
pub struct SeedInfo {
    pub seed_id: usize,
    pub edge_num: usize,
    pub exec_time_us: usize,
    pub len: usize,
    pub match_value: u16,
    pub match_value_sum: usize,
    pub run_ratio: usize,
}

impl SeedInfo {
    pub fn new(seed_id: usize, edge_num: usize) -> Self {
        Self {
            seed_id,
            edge_num,
            exec_time_us: 0,
            len: 0,
            match_value: 0,
            match_value_sum: 1,
            run_ratio: 0,
        }
    }
}

impl Default for SeedInfo {
    fn default() -> Self {
        Self {
            seed_id: 0,
            edge_num: 0,
            exec_time_us: 0,
            len: 0,
            match_value: 0,
            match_value_sum: 1,
            run_ratio: 0,
        }
    }
}

// Only use seed_id to impl Hash and Eq.
impl Hash for SeedInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.seed_id.hash(state);
    }
}

impl PartialEq for SeedInfo {
    fn eq(&self, other: &Self) -> bool {
        self.seed_id == other.seed_id
    }
}

impl Eq for SeedInfo {}