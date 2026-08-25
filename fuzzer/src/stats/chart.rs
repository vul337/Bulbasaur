use super::*;
use crate::{branches::GlobalBranches, depot::Depot};
use colored::*;
use serde_derive::Serialize;
use std::sync::Arc;

#[derive(Default, Serialize)]
pub struct ChartStats {
    init_time: TimeIns,
    track_time: TimeDuration,

    edge_data: CovData,
    branch_data: CovData,

    num_rounds: Counter,
    num_exec: Counter,
    speed: Average,

    avg_exec_time: Average,
    avg_edge_num: Average,

    num_inputs: Counter,
    num_hangs: Counter,
    num_crashes: Counter,

    reached_branches: Counter,
    branch_favor_seeds: Counter,
    bit_favor_seeds: Counter,

    pub timeout: Counter,
    fuzz: FuzzStats,
}

impl ChartStats {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn sync_from_local(&mut self, local: &mut LocalStats) {
        self.num_rounds.count();

        local.avg_edge_num.sync(&mut self.avg_edge_num);
        local.avg_exec_time.sync(&mut self.avg_exec_time);

        let st = self.fuzz.get_mut(local.fuzz_type.index());
        st.time += local.start_time.into();

        st.num_exec += local.num_exec;
        self.num_exec += local.num_exec;

        // if has new
        st.num_inputs += local.num_inputs;
        self.num_inputs += local.num_inputs;
        st.num_hangs += local.num_hangs;
        self.num_hangs += local.num_hangs;
        st.num_crashes += local.num_crashes;
        self.num_crashes += local.num_crashes;
        st.num_branches += local.num_branches;
        st.num_edges += local.num_edges;

    }

    pub fn sync_from_global(&mut self, depot: &Arc<Depot>, gb: &Arc<GlobalBranches>) {
        self.get_speed();
        // self.iter_pq(depot);
        self.sync_from_branches(gb);
        self.branch_favor_seeds = depot.get_branch_priority_num().into();
        self.bit_favor_seeds = depot.get_bit_priority_num().into();
    }

    fn sync_from_branches(&mut self, gb: &Arc<GlobalBranches>) {
        self.edge_data = {
            let (a, b, c) = gb.get_edge_stats();
            CovData(a, b, c)
        };
        
        self.branch_data = {
            let (x, y, z) = gb.get_branch_stats();
            CovData(x, y, z)
        };

        self.reached_branches = gb.get_reached_branches().into();
    }

    fn get_speed(&mut self) {
        let t: TimeDuration = self.init_time.into();
        let d: time::Duration = t.into();
        let ts = d.as_secs() as f64;
        let speed = if ts > 0.0 {
            let v: usize = self.num_exec.into();
            v as f64 / ts
        } else {
            0.0
        };
        self.speed = Average::new(speed as f32, 0);
    }

    pub fn mini_log(&self) -> (String, String) {
        (
            String::from("time_sec, edges_cur, edges_pct, branches_cur, branches_pct, inputs, hangs, crashes, execs"),
            format!(
                "{}, {}, {}, {}, {}, {}, {}, {}, {}",
                self.init_time.0.elapsed().as_secs(),
                self.edge_data.0,
                self.edge_data.2,
                self.branch_data.0,
                self.branch_data.2,
                self.num_inputs.0,
                self.num_hangs.0,
                self.num_crashes.0,
                self.num_exec.0,
            )
        )
    }

}

impl fmt::Display for ChartStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            r#"
{}
{}
    TIMING   |     RUN: {},   TIMEOUT: {}
    EDGE     |     COV: {},   TOTAL: {},   PER: {}%
    BRANCH   |   REACH: {},   COV: {},   TOTAL: {},   PER: {}%
    EXECS    |   TOTAL: {},     ROUND: {}
    SPEED    |  PERIOD: {:6}r/s    TIME: {}us, 
    FOUND    |    PATH: {},     HANGS: {},   CRASHES: {}
    DEPOT    |  BR_SEEDS: {}, BIT_SEEDS: {}
{}
{}
"#,
            get_bunny_logo().bold(),
            " -- OVERVIEW -- ".blue().bold(),
            self.init_time,
            self.timeout.0,
            self.edge_data.0,
            self.edge_data.1,
            self.edge_data.2,
            self.reached_branches,
            self.branch_data.0,
            self.branch_data.1,
            self.branch_data.2,
            self.num_exec,
            self.num_rounds,
            self.speed,
            self.avg_exec_time,
            self.num_inputs,
            self.num_hangs,
            self.num_crashes,
            self.branch_favor_seeds,
            self.bit_favor_seeds,
            " -- FUZZ -- ".blue().bold(),
            self.fuzz,
        )
    }
}
