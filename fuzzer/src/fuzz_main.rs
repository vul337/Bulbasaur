use crate::{parse_raw_section, stats::*};
use bulbasaur_common::defs;
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use std::{
    fs,
    io::prelude::*,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, RwLock,
    },
    thread, time, env,
};

use crate::{bind_cpu, branches, check_dep, command, depot, executor, fuzz_loop, stats, extras, llm_loop};
use libc;
use pretty_env_logger;

pub fn fuzz_main(
    in_dir: &str,
    out_dir: &str,
    pargs: Vec<String>,
    bind: Option<usize>,
    num_jobs: usize,
    mem_limit: u64,
    time_limit: u64,
    scheduled_mutation: bool,
    full_target: &str,
    trace_target: &str,
    extras_path: Vec<&str>,
    llm_port: u16,
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
        scheduled_mutation,
        llm_port != 0,
    );

    check_dep::check_dep(in_dir, out_dir, &command_option);
    
    // To support dynamic linking binary, bulbasaur don't read section data from binary.
    // let (full_edge_num, full_branch_num, edge_to_pred_branch_dict, 
    //     _, branch_type_dict, trace_branch_type_dict) = analyse_bin::analyse_binary(command_option.full.0.clone(), command_option.trace.0.clone());

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

    assert!(fast_map_size_data.real_map_size == trace_map_size_data.real_map_size,
            "The edge map size of the fast target does not match that of the trace target.");

    // Parse extra dictionary.
    let extras_data = extras::load_extras(extras_path);

    let depot = Arc::new(depot::Depot::new(seeds_dir, &bulbasaur_out_dir, extras_data));
    info!("{:?}", depot.dirs);

    let stats = Arc::new(RwLock::new(stats::ChartStats::new()));
    let global_branches = Arc::new(branches::GlobalBranches::new(num_jobs, fast_map_size_data, full_map_size_data, trace_map_size_data, edge_to_pred_branch_dict, branch_type_dict, trace_branch_type_dict));

    let fuzzer_stats = create_stats_file_and_write_pid(&bulbasaur_out_dir);
    let running = Arc::new(AtomicBool::new(true));
    set_signal_handlers(running.clone());

    let mut executor = executor::Executor::new(
        command_option.specify(0),
        global_branches.clone(),
        depot.clone(),
        stats.clone(),
    );

    // Reset the time limit according to the exec time in sync.
    let (max_exec_us, avg_exec_us) = depot::sync_depot(&mut executor, running.clone(), &depot.dirs.seeds_dir);

    // Set per-execution timeout from the slowest seed seen during sync, with a 20%
    // headroom factor.  Clamped to [5 ms, user-specified limit] so we never set an
    // unreasonably tight or loose timeout.
    {
        let mut auto_timeout_ms = ((max_exec_us as f64) * 1.2 / 1000.0).round() as u64;
        auto_timeout_ms = auto_timeout_ms.clamp(5, command_option.time_limit);
        
        command_option.time_limit = auto_timeout_ms;
        info!("Set the time limit to {}", auto_timeout_ms);
        stats.write().unwrap().timeout = (auto_timeout_ms as usize).into();
    }

    if depot.get_branch_priority_num() == 0 {
        // Native LLVM PCGuard fallback targets intentionally have no
        // Bulbasaur branch frontier.  Their edge queue is still usable for
        // ordinary fuzzing, so do not abort before the search loop starts.
        warn!("No seeds in branch queue; continuing with edge-priority fuzzing.");
    }
    assert!(depot.get_bit_priority_num() != 0, "No valid seeds in bit queue.");

    if depot.empty() {
        error!("Failed to find any branches during dry run.");
        error!("Please ensure that the binary has been instrumented and/or input directory is populated.");
        error!(
            "Please ensure that seed directory - {:?} has any file.",
            depot.dirs.seeds_dir
        );
        panic!("No valid seeds found after sync — aborting.");
    }

    // Adjust total havoc executino num according to avg_exec_us.
    if avg_exec_us > 50000 {
        command_option.havoc_div = 10
    } else if avg_exec_us > 20000 {
        command_option.havoc_div = 5
    } else if avg_exec_us > 10000 {
        command_option.havoc_div = 2
    };

    info!("{:?}", command_option);

    // Start Agent loop thread if llm_port is valid
    if llm_port != 0 {
        let llm_branches = global_branches.clone();
        let fuzzer_command = command_option.clone();
        let running = running.clone();
        let llm_port_val = llm_port;
        thread::spawn(move || {
            llm_loop::llm_loop(llm_branches, llm_port_val, fuzzer_command, running);
        });
        info!("Agent loop thread started on port {}", llm_port);
    }

    let (handles, _) = init_cpus_and_run_fuzzing_threads(
        bind,
        num_jobs,
        &running,
        &command_option,
        &global_branches,
        &depot,
        &stats,
    );

    let log_file = match fs::File::create(bulbasaur_out_dir.join(defs::BULBASAUR_LOG_FILE)) {
        Ok(a) => a,
        Err(e) => {
            error!("FATAL: Could not create log file: {:?}", e);
            panic!("Could not create log file: {:?}", e);
        },
    };
    main_thread_sync_and_log(
        log_file,
        out_dir,
        running.clone(),
        &depot,
        &global_branches,
        &stats,
    );

    for handle in handles {
        if handle.join().is_err() {
            error!("Error happened in fuzzing thread!");
        }
    }

    match fs::remove_file(&fuzzer_stats) {
        Ok(_) => (),
        Err(e) => warn!("Could not remove fuzzer stats file: {:?}", e),
    };
}

fn initialize_directories(in_dir: &str, out_dir: &str) -> (PathBuf, PathBuf) {
    let bulbasaur_out_dir = PathBuf::from(out_dir);

    // Create output directory if it doesn't exist
    if !bulbasaur_out_dir.exists() {
        fs::create_dir_all(&bulbasaur_out_dir).expect("Failed to create output directory!");
    }
    
    // Check and remove/error on existing directories that should not exist
    let crashes_dir = bulbasaur_out_dir.join(defs::CRASHES_DIR);
    let hangs_dir = bulbasaur_out_dir.join(defs::HANGS_DIR);
    let queue_dir = bulbasaur_out_dir.join(defs::INPUTS_DIR);
    
    if crashes_dir.exists() {
        panic!("Directory '{}' already exists! Please remove it before starting fuzzing.", crashes_dir.display());
    }
    if hangs_dir.exists() {
        panic!("Directory '{}' already exists! Please remove it before starting fuzzing.", hangs_dir.display());
    }
    if queue_dir.exists() {
        panic!("Directory '{}' already exists! Please remove it before starting fuzzing.", queue_dir.display());
    }
    
    // Check and remove/error on existing files that should not exist
    let chart_stat_file = bulbasaur_out_dir.join(defs::CHART_STAT_FILE);
    let plot_data_file = bulbasaur_out_dir.join(defs::BULBASAUR_LOG_FILE);
    
    if chart_stat_file.exists() {
        panic!("File '{}' already exists! Please remove it before starting fuzzing.", chart_stat_file.display());
    }
    if plot_data_file.exists() {
        panic!("File '{}' already exists! Please remove it before starting fuzzing.", plot_data_file.display());
    }
    
    let seeds_dir = PathBuf::from(in_dir);

    (seeds_dir, bulbasaur_out_dir)
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

fn create_stats_file_and_write_pid(bulbasaur_out_dir: &PathBuf) -> PathBuf {
    // To be compatible with AFL.
    let fuzzer_stats = bulbasaur_out_dir.join("fuzzer_stats");
    let pid = unsafe { libc::getpid() as usize };
    let mut buffer = match fs::File::create(&fuzzer_stats) {
        Ok(a) => a,
        Err(e) => {
            error!("Could not create stats file: {:?}", e);
            panic!();
        },
    };
    write!(buffer, "fuzzer_pid : {}", pid).expect("Could not write to stats file");
    fuzzer_stats
}

fn init_cpus_and_run_fuzzing_threads(
    bind: Option<usize>,
    num_jobs: usize,
    running: &Arc<AtomicBool>,
    command_option: &command::CommandOpt,
    global_branches: &Arc<branches::GlobalBranches>,
    depot: &Arc<depot::Depot>,
    stats: &Arc<RwLock<stats::ChartStats>>,
) -> (Vec<thread::JoinHandle<()>>, Arc<AtomicUsize>) {
    let child_count = Arc::new(AtomicUsize::new(0));
    let mut handlers = vec![];
    let free_cpus = match bind {
        None => bind_cpu::find_free_cpus(num_jobs),
        Some(start_cid) => {
            let max_num = num_cpus::get();
            (start_cid..max_num).collect()
        },
    };
    let free_cpus_len = free_cpus.len();
    let bind_cpus = if env::var("DISABLE_BULBASAUR_BIND").is_ok() {
        info!("DISABLE_BULBASAUR_BIND detected, bulbasaur will not bind cpu.");
        false
    } else {
        if free_cpus_len < num_jobs {
            // warn!("The number of free cpus is less than the number of jobs. Will not bind any thread to any cpu.");
            error!("The number of free cpus is less than the number of jobs. Please reduce thread count.");
            panic!();
        } else {
            true
        }
    };
    
    for thread_id in 0..num_jobs {
        let c = child_count.clone();
        let r = running.clone();
        let cmd = command_option.specify(thread_id + 1);
        let d = depot.clone();
        let b = global_branches.clone();
        let s = stats.clone();
        let cid = if bind_cpus { free_cpus[thread_id] } else { 0 };
        let handler = thread::spawn(move || {
            c.fetch_add(1, Ordering::SeqCst);
            if bind_cpus {
                bind_cpu::bind_thread_to_cpu_core(cid);
            }
            fuzz_loop::fuzz_loop(r, cmd, d, b, s);
        });
        handlers.push(handler);
    }
    (handlers, child_count)
}

fn main_thread_sync_and_log(
    mut log_file: fs::File,
    out_dir: &str,
    running: Arc<AtomicBool>,
    depot: &Arc<depot::Depot>,
    global_branches: &Arc<branches::GlobalBranches>,
    stats: &Arc<RwLock<stats::ChartStats>>,
) {
    show_stats(&mut log_file, depot, global_branches, stats, true);
    while running.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::from_secs(5));
        show_stats(&mut log_file, depot, global_branches, stats, false);
    }
}
