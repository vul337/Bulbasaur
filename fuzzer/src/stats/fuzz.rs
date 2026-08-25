use super::*;
use serde_derive::Serialize;

#[derive(Clone, Copy, Default, Serialize)]
pub struct StrategyStats {
    pub time: TimeDuration,
    pub num_exec: Counter,
    pub num_inputs: Counter,
    pub num_hangs: Counter,
    pub num_crashes: Counter,
    pub num_edges: Counter,
    pub num_branches: Counter,
}

impl fmt::Display for StrategyStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "EXEC: {}, TIME: {}, FOUND: {} - {} - {}",
            self.num_exec,
            self.time,
            self.num_inputs,
            self.num_hangs,
            self.num_crashes,
        )
    }
}

#[derive(Clone, Default, Serialize)]
pub struct FuzzStats([StrategyStats; fuzz_type::FUZZ_TYPE_NUM]);

impl FuzzStats {
    #[inline]
    pub fn get_mut(&mut self, i: usize) -> &mut StrategyStats {
        assert!(i < fuzz_type::FUZZ_TYPE_NUM);
        &mut self.0[i]
    }
}

impl fmt::Display for FuzzStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let contents = self
            .0
            .iter()
            .enumerate()
            .map(|(i, s)| {
                format!(
                    "  {:>8} | {}",
                    fuzz_type::get_fuzz_type_name(i).to_uppercase(),
                    s
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        write!(f, "{}", contents)
    }
}
