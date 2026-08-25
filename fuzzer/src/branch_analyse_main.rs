use crate::{parse_raw_section};
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    thread,
};

use std::fs::File;
use std::io::{Write, Result};
use std::path::Path;

use crate::{branches, check_dep, command, depot, executor, stats};
use pretty_env_logger;


pub fn branch_analyse_main(
    in_dir: &str,
    out_dir: &str,
    pargs: Vec<String>,
    mem_limit: u64,
    time_limit: u64,
    full_target: &str,
    trace_target: &str,
) {
    pretty_env_logger::init();

    let (seeds_dir, bulbasaur_out_dir) = initialize_directories(in_dir, out_dir);
    let mut command_option = command::CommandOpt::new(
        pargs,
        full_target,
        trace_target,
        &bulbasaur_out_dir,
        mem_limit,
        time_limit,
        false,
        false,
    );

    check_dep::check_dep(in_dir, out_dir, &command_option);
   
    // Bulbasaur will get section data from pipes.
    let (fast_map_size_data, 
        full_map_size_data, 
        trace_map_size_data, 
        use_shmem_fuzz, 
        branch_type_raw_data, 
        edge_to_pred_branch_raw_data,
        trace_branch_type_raw_data) = executor::Executor::get_crucial_data_from_binary(&command_option);

    let branch_type_dict = parse_raw_section::parse_branch_type(branch_type_raw_data);
    let (edge_to_pred_branch_dict, branch_boundary) = parse_raw_section::parse_edge_to_pred_branch(edge_to_pred_branch_raw_data);
    let trace_branch_type_dict = parse_raw_section::parse_branch_type(trace_branch_type_raw_data);

    if use_shmem_fuzz {
        command_option.use_shmem_fuzz = true;
        command_option.is_stdin = false;
    }

    command_option.edge_to_pred_branch_dict = edge_to_pred_branch_dict.clone();
    command_option.branch_boundary = branch_boundary;

    assert!(fast_map_size_data.real_branch_map_size == full_map_size_data.real_branch_map_size, 
            "The branch map size of the fast target does not match that of the full target.");

    assert!(fast_map_size_data.real_map_size == trace_map_size_data.real_map_size);

    let depot = Arc::new(depot::Depot::new(seeds_dir, &bulbasaur_out_dir, Vec::new()));
    info!("{:?}", depot.dirs);

    let stats = Arc::new(RwLock::new(stats::ChartStats::new()));
    let global_branches = Arc::new(branches::GlobalBranches::new(1, fast_map_size_data, full_map_size_data, trace_map_size_data, edge_to_pred_branch_dict, branch_type_dict, trace_branch_type_dict));

    let running = Arc::new(AtomicBool::new(true));
    set_signal_handlers(running.clone());

    let mut executor = executor::Executor::new(
        command_option.specify(0),
        global_branches.clone(),
        depot.clone(),
        stats.clone(),
    );

    let (_, _) = depot::sync_depot(&mut executor, running.clone(), &depot.dirs.seeds_dir);

    running.store(false, Ordering::SeqCst);

    // Write branch coverage to file
    write_branch_coverage(&executor, &bulbasaur_out_dir).unwrap();

    // Final output
    info!("Branch analysis completed. Results saved to: {:?}", bulbasaur_out_dir);
}


fn initialize_directories(in_dir: &str, out_dir: &str) -> (PathBuf, PathBuf) {
    let bulbasaur_out_dir = PathBuf::from(out_dir);

    fs::create_dir(&bulbasaur_out_dir).expect("Output directory has existed!");
    let seeds_dir =PathBuf::from(in_dir);

    (seeds_dir, bulbasaur_out_dir)
}

fn write_branch_coverage(executor: &executor::Executor, out_dir: &Path) -> Result<()> {
    let (reached, covered, total, percent) = executor.branches.get_branch_data();

    let mut output = String::new();
    output += &format!("Reached branches: {:?}\n", reached);
    output += &format!("Covered branches: {}\n", covered);
    output += &format!("Total branches: {}\n", total);
    output += &format!("Coverage percent: {:.2}%\n", percent);

    let path = Path::new(out_dir).join("branch_coverage.stat");

    fs::create_dir_all(out_dir)?;

    let mut file = File::create(path)?;
    file.write_all(output.as_bytes())?;

    Ok(())
}

fn set_signal_handlers(r: Arc<AtomicBool>) {
    let mut signals = Signals::new(&[SIGINT, SIGTERM, SIGHUP]).expect("Failed to register signal handlers");
    let r_clone = Arc::clone(&r);

    thread::spawn(move || {
        for sig in signals.forever() {
            match sig {
                SIGINT => log::warn!("Received SIGINT (Ctrl+C)"),
                SIGTERM => log::warn!("Received SIGTERM (Termination)"),
                SIGHUP => log::warn!("Received SIGHUP (Hangup)"),
                _ => log::warn!("Received other signal: {}", sig),
            }

            r_clone.store(false, Ordering::SeqCst);
            break; // exit loop after first signal
        }
    });
}