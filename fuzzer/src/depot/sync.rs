use super::*;
use crate::executor::Executor;
use crate::fuzz_type::FuzzType;
use bulbasaur_common::config;
use walkdir::WalkDir;
use std::cmp::max;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};


/// Synchronize initial seeds from the seed directory.
/// 
/// Returns the maximum and average execution time (in microseconds),
/// which are used for automatic timeout configuration and power scheduling.
pub fn sync_depot(executor: &mut Executor, running: Arc<AtomicBool>, dir: &Path) -> (usize, usize) {
    executor.local_stats.register(FuzzType::Sync);
    let mut max_sync_exec_us = 0;
    let mut total_sync_exec_us = 0;
    let mut sync_num = 0;
    
    for entry in WalkDir::new(&dir).into_iter().filter_map(Result::ok) {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        let path = entry.path();
        if path.is_file() {            
            let mut buf = read_from_file(path);

            if buf.len() > config::MAX_INPUT_LEN {
                warn!("Seed too long, read it partially: {:?}", path);
                buf.truncate(config::MAX_INPUT_LEN);
            }

            let (is_normal, exec_us) = executor.run_sync(&buf, SeedInfo::default());
            if !is_normal {
                warn!("Initial seed {:?} is abnormal, skip it.", path);
                continue
            }
            total_sync_exec_us += exec_us;
            max_sync_exec_us = max(max_sync_exec_us, exec_us);

            sync_num += 1;
        }
    }
    info!("sync {} file from seeds.", executor.local_stats.num_inputs);
    executor.update_log();

    if sync_num == 0 {
        error!("No valid initial seeds were synchronized; all seeds were abnormal or the seed dir was empty.");
        return (0, 0);
    }

    (max_sync_exec_us, total_sync_exec_us / sync_num)
}
