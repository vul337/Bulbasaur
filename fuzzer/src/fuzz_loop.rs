use crate::{
    branches::GlobalBranches, command::CommandOpt, depot::Depot,
    executor::Executor, search::*, stats,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

pub fn fuzz_loop(
    running: Arc<AtomicBool>,
    cmd_opt: CommandOpt,
    depot: Arc<Depot>,
    global_branches: Arc<GlobalBranches>,
    global_stats: Arc<RwLock<stats::ChartStats>>,
) {
    let mut search_server = SearchServer::new(&cmd_opt);
    let mut executor = Executor::new(
        cmd_opt,
        global_branches,
        depot.clone(),
        global_stats.clone(),
    );

    // Main full loop.
    while running.load(Ordering::Relaxed) {
        let (queue_id, seed_info) = depot.get_top_seed();

        {
            let mut handler = SearchHandler::new(running.clone(), &mut executor, seed_info);
            search_server.mutate(&mut handler);
            let queue_rewards = handler.queue_rewards.clone();

            // Update global beta values in depot.
            executor.depot.update_beta_values_in_depot(queue_id, queue_rewards);
        }
    }
}
