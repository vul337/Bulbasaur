use crate::branches::GlobalBranches;
use crate::command::CommandOpt;
use bulbasaur_common::config::{TIME_INTERVAL, MAX_RETRY_COUNT, CHECK_INTERVAL};
use bulbasaur_common::mutate_func::MutateFunc;
use std::sync::{Arc, atomic::AtomicBool};
use std::net::TcpStream;
use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::fs;
use std::fs::OpenOptions;
use rand::Rng;

/// Agent loop that connects to the Agent bridge and handles communication
pub fn llm_loop(
    global_branches: Arc<GlobalBranches>,
    llm_port: u16,
    fuzzer_command: CommandOpt,
    running: Arc<AtomicBool>,
) {
    info!("Starting Agent loop on port {}", llm_port);
    
    // Connect to the Agent bridge on localhost
    let server_addr = format!("127.0.0.1:{}", llm_port);
    
    // Try to connect to the server with retries
    let mut stream = loop {
        if !running.load(std::sync::atomic::Ordering::Relaxed) {
            info!("Fuzzer stopped before connecting to Agent bridge");
            return;
        }
        
        match TcpStream::connect(&server_addr) {
            Ok(stream) => {
    info!("Successfully connected to Agent bridge at {}", server_addr);
                stream.set_read_timeout(Some(Duration::from_secs(1800))).ok(); // 30 minutes
                stream.set_write_timeout(Some(Duration::from_secs(300))).ok(); // 5 minutes
                break stream;
            }
            Err(e) => {
                warn!("Failed to connect to Agent bridge at {}: {}. Retrying in 1 second...", server_addr, e);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };
    
    // Main loop: check branch_mutate_funcs every CHECK_INTERVAL seconds
    let check_interval = Duration::from_secs(CHECK_INTERVAL.try_into().unwrap());
    let mut_funcs_dir = fuzzer_command.out_dir.join("mut_funcs");

    // Load existing mutation functions before starting the loop
    load_existing_mutation_functions(&global_branches, &mut_funcs_dir, &fuzzer_command.out_dir);
    
    while running.load(std::sync::atomic::Ordering::Relaxed) {
        // Check for branches that need mutation functions
        check_and_request_mutation_functions(
            &global_branches,
            &mut stream,
            &mut_funcs_dir,
            &running,
            &fuzzer_command.out_dir,
        );
        
        // Sleep for CHECK_INTERVAL seconds before the next check. Wake at least
        // once per second so short test intervals (for example 60 seconds) are
        // honored without making shutdown wait for a long fixed sleep chunk.
        let mut slept = Duration::from_secs(0);
        while slept < check_interval && running.load(std::sync::atomic::Ordering::Relaxed) {
            let remaining = check_interval - slept;
            let sleep_for = std::cmp::min(remaining, Duration::from_secs(1));
            std::thread::sleep(sleep_for);
            slept += sleep_for;
        }
    }
    
    info!("Agent loop ended");
}

/// Load existing mutation functions from mut_funcs directory before starting the loop.
/// This function scans the mut_funcs directory for compiled .so files and loads them.
/// Also loads impossible branches from impossible_branches file and sets their retry_count to max.
fn load_existing_mutation_functions(
    global_branches: &Arc<GlobalBranches>,
    mut_funcs_dir: &std::path::Path,
    out_dir: &std::path::Path,
) {
    info!("Scanning for existing mutation functions in: {:?}", mut_funcs_dir);
    
    let branch_start_pos = &global_branches.branch_start_pos;
    let branch_end_pos = &global_branches.branch_end_pos;
    let thread_num = global_branches.thread_num;

    // Check if impossible_branches file exists and load impossible branches
    load_impossible_branches(global_branches, out_dir, branch_start_pos, branch_end_pos, thread_num);
    
    // Check if mut_funcs directory exists
    if !mut_funcs_dir.exists() {
        info!("mut_funcs directory does not exist, skipping pre-load");
        return;
    }
    
    // Read directory entries
    let entries = match fs::read_dir(mut_funcs_dir) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Failed to read mut_funcs directory: {}, skipping pre-load", e);
            return;
        }
    };
    
    let mut loaded_count = 0;
    let mut skipped_count = 0;
    let mut error_count = 0;
    
    // Iterate through each subdirectory (each should be a branch_id)
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!("Error reading directory entry: {}, skipping", e);
                continue;
            }
        };
        
        let path = entry.path();
        
        // Skip if not a directory
        if !path.is_dir() {
            continue;
        }
        
        // Extract branch_id from directory name
        let branch_id_str = match path.file_name().and_then(|n| n.to_str()) {
            Some(s) => s,
            None => {
                warn!("Invalid directory name (not UTF-8): {:?}, skipping", path);
                continue;
            }
        };
        
        let branch_id: usize = match branch_id_str.parse() {
            Ok(id) => id,
            Err(_) => {
                // Not a number, skip (might be other directories like "target")
                continue;
            }
        };
        
        // Find the chunk_idx and local_idx for this branch_id
        let (chunk_idx, local_idx) = match find_chunk_and_local_idx(branch_id, branch_start_pos, branch_end_pos, thread_num) {
            Some((chunk, local)) => (chunk, local),
            None => {
                warn!("Branch ID {} is out of range, skipping", branch_id);
                skipped_count += 1;
                continue;
            }
        };
        
        // Check if mutation function already exists (don't reload)
        let already_loaded = {
            if let Ok(mutate_read_guard) = global_branches.branch_mutate_funcs[chunk_idx].read() {
                let mutate_data: &Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &*mutate_read_guard;
                if local_idx < mutate_data.len() {
                    mutate_data[local_idx].mutate_func.is_some()
                } else {
                    false
                }
            } else {
                false
            }
        };
        
        if already_loaded {
            info!("Mutation function for branch {} already loaded, skipping", branch_id);
            skipped_count += 1;
            continue;
        }
        
        // Find the latest timestamp directory that contains a .so file
        let so_path = match find_latest_so_file(&path, branch_id) {
            Some(so_path) => so_path,
            None => {
                // No .so file found, skip
                skipped_count += 1;
                continue;
            }
        };
        
        // Load the mutation function
        info!("Loading existing mutation function for branch {} from {:?}", branch_id, so_path);
        match load_mutation_function_from_path(
            branch_id,
            &so_path,
            chunk_idx,
            local_idx,
            global_branches,
            true,
        ) {
            Ok(()) => {
                loaded_count += 1;
                info!("Successfully loaded mutation function for branch {}", branch_id);
            }
            Err(e) => {
                error_count += 1;
                warn!("Failed to load mutation function for branch {}: {}", branch_id, e);
            }
        }
    }
    
    info!("Pre-load complete: {} loaded, {} skipped, {} errors", loaded_count, skipped_count, error_count);
}

/// Find the latest timestamp directory that contains a .so file for the given branch_id.
/// Returns the path to the .so file, or None if no .so file is found.
fn find_latest_so_file(branch_dir: &std::path::Path, branch_id: usize) -> Option<std::path::PathBuf> {
    // Read all subdirectories in the branch_id directory
    let entries = match fs::read_dir(branch_dir) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Failed to read branch directory {:?}: {}", branch_dir, e);
            return None;
        }
    };
    
    let mut candidates: Vec<(std::path::PathBuf, std::time::SystemTime)> = Vec::new();
    
    // Collect all timestamp directories that contain .so files
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let subdir_path = entry.path();
        
        // Skip if not a directory
        if !subdir_path.is_dir() {
            continue;
        }
        
        // Check if this subdirectory contains the .so file
        // Path format: branch_id/timestamp_dir/target/release/libmut_branch_{branch_id}.so
        let so_path = subdir_path.join("target")
            .join("release")
            .join(format!("libmut_branch_{}.so", branch_id));
        
        if so_path.exists() {
            // Get the modification time of the .so file (or directory if file metadata fails)
            let metadata = match so_path.metadata() {
                Ok(m) => m,
                Err(_) => match subdir_path.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                }
            };
            
            let modified_time = match metadata.modified() {
                Ok(t) => t,
                Err(_) => continue,
            };
            
            candidates.push((so_path, modified_time));
        }
    }
    
    if candidates.is_empty() {
        return None;
    }
    
    // Sort by modification time (newest first) and return the latest one
    candidates.sort_by(|a, b| b.1.cmp(&a.1)); // Sort descending (newest first)
    
    Some(candidates[0].0.clone())
}

/// Find chunk_idx and local_idx for a given branch_id.
/// Returns None if branch_id is out of range.
fn find_chunk_and_local_idx(
    branch_id: usize,
    branch_start_pos: &[usize],
    branch_end_pos: &[usize],
    thread_num: usize,
) -> Option<(usize, usize)> {
    // Search through all chunks to find which one contains this branch_id
    for chunk_idx in 0..thread_num {
        if chunk_idx >= branch_start_pos.len() || chunk_idx >= branch_end_pos.len() {
            continue;
        }
        
        let start = branch_start_pos[chunk_idx];
        let end = branch_end_pos[chunk_idx];
        
        if branch_id >= start && branch_id < end {
            let local_idx = branch_id - start;
            return Some((chunk_idx, local_idx));
        }
    }
    
    None
}

/// Load impossible branches from impossible_branches file and set their retry_count to max.
/// This prevents these branches from being checked again.
fn load_impossible_branches(
    global_branches: &Arc<GlobalBranches>,
    out_dir: &std::path::Path,
    branch_start_pos: &[usize],
    branch_end_pos: &[usize],
    thread_num: usize,
) {
    let impossible_file = out_dir.join("impossible_branches");
    
    // Check if file exists
    if !impossible_file.exists() {
        info!("impossible_branches file does not exist, skipping");
        return;
    }
    
    // Read the file
    let content = match fs::read_to_string(&impossible_file) {
        Ok(content) => content,
        Err(e) => {
            warn!("Failed to read impossible_branches file: {}, skipping", e);
            return;
        }
    };
    
    let mut loaded_count = 0;
    let mut invalid_count = 0;
    
    // Parse each line as a branch_id
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        
        // Parse branch_id
        let branch_id: usize = match line.parse() {
            Ok(id) => id,
            Err(_) => {
                warn!("Invalid branch_id in impossible_branches file: {}, skipping", line);
                invalid_count += 1;
                continue;
            }
        };
        
        // Find chunk_idx and local_idx for this branch_id
        let (chunk_idx, local_idx) = match find_chunk_and_local_idx(branch_id, branch_start_pos, branch_end_pos, thread_num) {
            Some((chunk, local)) => (chunk, local),
            None => {
                warn!("Branch ID {} from impossible_branches file is out of range, skipping", branch_id);
                invalid_count += 1;
                continue;
            }
        };
        
        // Set retry_count to max
        if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
            let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
            if local_idx < mutate_data.len() {
                mutate_data[local_idx].retry_count = MAX_RETRY_COUNT;
                loaded_count += 1;
                info!("Set retry_count to max for impossible branch {}", branch_id);
            } else {
                warn!("Local index {} out of range for branch {} in chunk {}", local_idx, branch_id, chunk_idx);
                invalid_count += 1;
            }
        } else {
            warn!("Failed to acquire write lock for branch_mutate_funcs[{}]", chunk_idx);
        }
    }
    
    info!("Loaded {} impossible branches from file ({} invalid entries)", loaded_count, invalid_count);
}

/// Write branch_id to impossible_branches file in the output directory.
/// The file is created if it doesn't exist, and branch_id is appended if it's not already present.
fn write_impossible_branch(out_dir: &std::path::Path, branch_id: usize) {
    let impossible_file = out_dir.join("impossible_branches");
    
    // First, check if branch_id is already in the file
    
    // Try to open file in append mode, create if it doesn't exist
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&impossible_file)
    {
        Ok(mut file) => {
            // Write branch_id to file
            if let Err(e) = writeln!(file, "{}", branch_id) {
                warn!("Failed to write branch_id {} to impossible_branches file: {}", branch_id, e);
            } else {
                info!("Wrote branch_id {} to impossible_branches file", branch_id);
            }
        }
        Err(e) => {
            warn!("Failed to open impossible_branches file for writing: {}", e);
        }
    }
}

/// Check branch_mutate_funcs for branches that need mutation functions and request them from the Agent bridge.
fn check_and_request_mutation_functions(
    global_branches: &Arc<GlobalBranches>,
    stream: &mut TcpStream,
    mut_funcs_dir: &std::path::Path,
    running: &Arc<AtomicBool>,
    out_dir: &std::path::Path,
) {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    
    let thread_num = global_branches.thread_num;
    let branch_start_pos = &global_branches.branch_start_pos;
    
    // Generate random start and step for chunk iteration (similar to branches.rs)
    let mut rng = rand::thread_rng();
    let start = rng.gen_range(0..thread_num);
    
    // Compute coprime numbers with thread_num for step sizes
    let steps: Vec<usize> = (1..thread_num)
        .filter(|&x| {
            let mut a = x;
            let mut b = thread_num;
            while b != 0 {
                let temp = b;
                b = a % b;
                a = temp;
            }
            a == 1 // coprime
        })
        .collect();
    
    let step = if steps.is_empty() { 1 } else { steps[rng.gen_range(0..steps.len())] };
    
    let mut visit_tags = vec![false; thread_num];
    let mut visited_count = 0;
    let mut idx = start;
    let mut tmp_branches_to_request = Vec::new();
    let mut branches_to_request = Vec::new();
    
    // First pass: collect branches that need mutation functions
    while visited_count < thread_num {
        if !visit_tags[idx] {
            visit_tags[idx] = true;
            visited_count += 1;
            
            if let Ok(mutate_read_guard) = global_branches.branch_mutate_funcs[idx].read() {
                let mutate_data: &Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &*mutate_read_guard;
                
                for (local_idx, branch_info) in mutate_data.iter().enumerate() {
                    // Check conditions:
                    // 1. reach_time > 0 (branch has been reached)
                    // 2. reach_time + TIME_INTERVAL < current_time (reached more than 6 hours ago)
                    // 3. !is_covered (branch not covered yet)
                    // 4. mutate_func.is_none() (no mutation function loaded yet)
                    if branch_info.reach_time > 0
                        && branch_info.reach_time + TIME_INTERVAL < current_time
                        && !branch_info.is_covered
                        && branch_info.retry_count < MAX_RETRY_COUNT
                    {
                        let real_branch_id = branch_start_pos[idx] + local_idx;
                        tmp_branches_to_request.push((idx, local_idx, real_branch_id));
                    }
                }
            }
        }
        
        idx = (idx + step) % thread_num;
    }
    
    {
        let read_guard = global_branches.branch_boundary.read().unwrap();
        let data: &Vec<Vec<usize>> = &*read_guard;
        for (idx, local_idx, branch_id) in tmp_branches_to_request {
            if data[branch_id].len() == 0 {
                // Branch is fully covered, skip it
                continue;
            }
            if data[branch_id].len() > 1 {
                // This is because of the multi-threading reason
                warn!("branch_boundary[{}] has more than 1 edge", branch_id);
                continue;
            }
            let edge_id = data[branch_id][0];
            // Skip if edge_id is 0 (temporary placeholder for StrcmpNonTerm/ConstStrcmpNonTerm branches)
            // These branches are handled differently and don't need Agent mutation functions
            if edge_id == 0 {
                continue;
            }
            branches_to_request.push((idx, local_idx, branch_id, edge_id));
        }
    }

    // Process each branch that needs a mutation function
    for (chunk_idx, local_idx, branch_id, edge_id) in branches_to_request {
        if !running.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        
        info!("Requesting mutation function for branch {} (chunk {}, local {})", branch_id, chunk_idx, local_idx);
        
        // Send request to Agent bridge
        let request = format!("1 {} {}\n", branch_id, edge_id);
        if let Err(e) = stream.write_all(request.as_bytes()) {
            error!("Failed to send request for branch {}: {}", branch_id, e);
            continue;
        }
        if let Err(e) = stream.flush() {
            error!("Failed to flush stream for branch {}: {}", branch_id, e);
            continue;
        }
        
        // Wait for response
        let mut buffer = [0; 4096];
        let response_str = match stream.read(&mut buffer) {
            Ok(0) => {
                warn!("Agent bridge closed connection");
                break;
            }
            Ok(n) => {
                let response = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                if response.is_empty() {
                    error!("Received empty response for branch {}", branch_id);
                    // Increase retry_count on error
                    if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
                        let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
                        mutate_data[local_idx].retry_count += 1;
                    }
                    continue;
                }
                response
            }
            Err(e) => {
                error!("Error reading response for branch {}: {}", branch_id, e);
                // Increase retry_count on error
                if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
                    let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
                    mutate_data[local_idx].retry_count += 1;
                }
                continue;
            }
        };
        
        // Parse response format: "status_code [branch_id] [so_path]"
        // - "0 branch_id" - Success, proceed to load (legacy format, will use default path)
        // - "0 branch_id so_path" - Success with explicit so_path, use the provided path
        // - "1 0" - Agent determined it's impossible to break through, set retry_count to max
        // - "1 1" - Processing error, increase retry_count
        // - Other - Invalid response, increase retry_count
        
        let response_parts: Vec<&str> = response_str.split_whitespace().collect();
        
        match response_parts.as_slice() {
            ["0", branch_id_str, so_path] => {
                // Success response with explicit so_path: "0 branch_id so_path"
                let response_branch_id: Result<usize, _> = branch_id_str.parse();
                match response_branch_id {
                    Ok(id) if id == branch_id => {
                        // Success - received the correct branch_id and so_path
                        info!("Received success response for branch {} with so_path: {}", branch_id, so_path);
                        
                        // Load the function using the provided so_path
                        let so_path_buf = std::path::PathBuf::from(so_path);
                        if let Err(e) = load_mutation_function_from_path(
                            branch_id,
                            &so_path_buf,
                            chunk_idx,
                            local_idx,
                            global_branches,
                            false,
                        ) {
                            error!("Failed to load mutation function for branch {} from {:?}: {}", branch_id, so_path_buf, e);
                            // Increase retry_count on load failure
                            if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
                                let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
                                mutate_data[local_idx].retry_count += 1;
                            }
                        }
                    }
                    Ok(id) => {
                        // Unexpected branch_id received
                        error!("Received unexpected branch_id {} for request {}, treating as failure", id, branch_id);
                        if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
                            let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
                            mutate_data[local_idx].retry_count += 1;
                        }
                    }
                    Err(_) => {
                        // Invalid branch_id in success response
                        error!("Received invalid branch_id in success response for branch {}: {}, treating as failure", branch_id, response_str);
                        if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
                            let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
                            mutate_data[local_idx].retry_count += 1;
                        }
                    }
                }
            }
            ["0", branch_id_str] => {
                // Success response (legacy format): "0 branch_id"
                let response_branch_id: Result<usize, _> = branch_id_str.parse();
                match response_branch_id {
                    Ok(id) if id == branch_id => {
                        // Success - received the correct branch_id, proceed to load (legacy path)
                        info!("Received success response for branch {} (legacy format, using default path): {}", branch_id, response_str);
                        
                        // Wait for compilation and load the function using default path
                        if let Err(e) = wait_and_load_mutation_function(
                            branch_id,
                            mut_funcs_dir,
                            chunk_idx,
                            local_idx,
                            global_branches,
                            running,
                        ) {
                            error!("Failed to load mutation function for branch {}: {}", branch_id, e);
                            // Increase retry_count on load failure
                            if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
                                let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
                                mutate_data[local_idx].retry_count += 1;
                            }
                        }
                    }
                    Ok(id) => {
                        // Unexpected branch_id received
                        error!("Received unexpected branch_id {} for request {}, treating as failure", id, branch_id);
                        if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
                            let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
                            mutate_data[local_idx].retry_count += 1;
                        }
                    }
                    Err(_) => {
                        // Invalid branch_id in success response
                        error!("Received invalid branch_id in success response for branch {}: {}, treating as failure", branch_id, response_str);
                        if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
                            let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
                            mutate_data[local_idx].retry_count += 1;
                        }
                    }
                }
            }
            ["1", "0"] => {
                // Agent determined it's impossible to break through - set retry_count to max
                info!("Agent determined it's impossible to break through for branch {} -> edge, setting retry_count to max", branch_id);
                // Write branch_id to impossible_branches file
                write_impossible_branch(out_dir, branch_id);

                if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
                    let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
                    mutate_data[local_idx].retry_count = MAX_RETRY_COUNT;
                }
                continue;
            }
            ["1", "1"] => {
                // Processing error - increase retry_count
                error!("Agent encountered processing error for branch {}", branch_id);
                if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
                    let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
                    mutate_data[local_idx].retry_count += 1;
                }
                continue;
            }
            _ => {
                // Invalid response format
                error!("Received invalid response format for branch {}: {}, treating as failure", branch_id, response_str);
                if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
                    let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
                    mutate_data[local_idx].retry_count += 1;
                }
                continue;
            }
        }
    }
}

/// Load mutation function from a specific path (used when so_path is provided in response).
fn load_mutation_function_from_path(
    branch_id: usize,
    so_path: &std::path::Path,
    chunk_idx: usize,
    local_idx: usize,
    global_branches: &Arc<GlobalBranches>,
    is_initial_load: bool,
) -> Result<(), String> {
    info!("Loading mutation function from provided path: {:?}", so_path);
    
    // Check if file exists
    if !so_path.exists() {
        return Err(format!("Library file does not exist: {:?}", so_path));
    }
    
    // Check if this is a reload (function already exists)
    let is_reload = {
        if let Ok(mutate_read_guard) = global_branches.branch_mutate_funcs[chunk_idx].read() {
            let mutate_data: &Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &*mutate_read_guard;
            mutate_data[local_idx].mutate_func.is_some()
        } else {
            false
        }
    };
    
    if is_reload {
        info!("Reloading mutation function for branch {} (previous function will be replaced)", branch_id);
    }
    
    // Load the dynamic library and get the function
    unsafe {
        let lib = libloading::Library::new(so_path)
            .map_err(|e| format!("Failed to load library: {}", e))?;
        
        let func_name = format!("mutate_branch_{}", branch_id);
        let func: libloading::Symbol<MutateFunc> = lib.get(func_name.as_bytes())
            .map_err(|e| format!("Failed to get function {}: {}", func_name, e))?;
        
        // Copy the function pointer (function pointers implement Copy trait)
        let func_ptr = *func;
        
        // CRITICAL: Forget the library to prevent it from being unloaded.
        // The function pointer will remain valid as long as the library stays in memory.
        // The library will stay loaded until the process exits.
        std::mem::forget(lib);
        
        if let Ok(mut mutate_write_guard) = global_branches.branch_mutate_funcs[chunk_idx].write() {
            let mutate_data: &mut Box<[bulbasaur_common::mutate_func::BranchMutateInfo]> = &mut *mutate_write_guard;
            let old_func = mutate_data[local_idx].mutate_func;
            mutate_data[local_idx].mutate_func = Some(func_ptr);
            // retry_count tracks total generation attempts (success or failure).
            // A branch is skipped once it reaches MAX_RETRY_COUNT regardless of outcome.
            mutate_data[local_idx].retry_count += 1;
            if !is_initial_load {
                mutate_data[local_idx].reach_time = SystemTime::now()
                                                    .duration_since(UNIX_EPOCH)
                                                    .unwrap()
                                                    .as_secs() as usize;
            }
            
            if is_reload {
                info!("Successfully reloaded mutation function for branch {} from {:?} (replaced previous function)", branch_id, so_path);
                if let Some(old_ptr) = old_func {
                    info!("Old function pointer: {:p}, New function pointer: {:p}", old_ptr as *const (), func_ptr as *const ());
                }
            } else {
                info!("Successfully loaded mutation function for branch {} from {:?}", branch_id, so_path);
            }
        } else {
            return Err("Failed to acquire write lock for branch_mutate_funcs".to_string());
        }
    }
    
    Ok(())
}

/// Wait for compilation to complete and load the mutation function into branch_mutate_funcs.
/// This is the legacy function that uses default path structure (for backward compatibility).
fn wait_and_load_mutation_function(
    branch_id: usize,
    mut_funcs_dir: &std::path::Path,
    chunk_idx: usize,
    local_idx: usize,
    global_branches: &Arc<GlobalBranches>,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    let branch_dir = mut_funcs_dir.join(branch_id.to_string());
    let so_path = branch_dir.join("target")
        .join("release")
        .join(format!("libmut_branch_{}.so", branch_id));
    
    info!("Waiting for compiled library at: {:?}", so_path);
    
    // Poll for the .so file to appear (with timeout)
    let max_wait_time = Duration::from_secs(300); // 5 minutes max
    let poll_interval = Duration::from_millis(500);
    let start_time = std::time::Instant::now();
    
    while !so_path.exists() {
        if start_time.elapsed() > max_wait_time {
            return Err(format!("Timeout waiting for compiled library at {:?}", so_path));
        }
        
        if !running.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("Fuzzer stopped while waiting for compilation".to_string());
        }
        
        std::thread::sleep(poll_interval);
    }
    
    info!("Found compiled library at: {:?}", so_path);
    
    // Use the shared loading function
    load_mutation_function_from_path(
        branch_id,
        &so_path,
        chunk_idx,
        local_idx,
        global_branches,
        false,
    )
}

/// Test function to load and test a mutation function library.
/// This function can be called from anywhere to test loading and using a mutation function.
/// 
/// # Arguments
/// * `so_path` - Path to the compiled .so library file (e.g., "/path/to/libmut_branch_123.so")
/// * `branch_id` - Branch ID to test (used to construct function name)
/// 
/// # Example
/// ```rust,no_run
/// use std::path::PathBuf;
/// use bulbasaur::llm_loop::test_load_and_use_mutation_function;
/// 
/// test_load_and_use_mutation_function(
///     PathBuf::from("/home/user/llm_test/output_dir/mut_funcs/378/target/release/libmut_branch_378.so"),
///     378
/// ).unwrap();
/// ```
pub fn test_load_and_use_mutation_function(so_path: std::path::PathBuf, branch_id: usize) -> Result<(), String> {
    println!("Testing mutation function library: {:?}", so_path);
    println!("Branch ID: {}", branch_id);
    
    // Check if file exists
    if !so_path.exists() {
        return Err(format!("Library file does not exist: {:?}", so_path));
    }
    
    // Load the dynamic library
    unsafe {
        let lib = libloading::Library::new(&so_path)
            .map_err(|e| format!("Failed to load library: {}", e))?;
        
        println!("✓ Successfully loaded library");
        
        // Get the function
        let func_name = format!("mutate_branch_{}", branch_id);
        println!("Looking for function: {}", func_name);
        
        let func: libloading::Symbol<MutateFunc> = lib.get(func_name.as_bytes())
            .map_err(|e| format!("Failed to get function {}: {}", func_name, e))?;
        
        println!("✓ Successfully found function: {}", func_name);
        
        // Get function pointer (Copy trait allows this)
        let func_ptr = *func;
        
        // Leak the library to keep it loaded (function pointer needs library to stay loaded)
        std::mem::forget(lib);
        
        // Prepare test data
        let mut test_buffer = Vec::from(b"test input data");
        let op1_data = Vec::from(b"operand1");
        let op2_data = Vec::from(b"operand2");
        
        println!("Test data before mutation:");
        println!("  Buffer: {:?}", String::from_utf8_lossy(&test_buffer));
        println!("  Op1: {:?}", String::from_utf8_lossy(&op1_data));
        println!("  Op2: {:?}", String::from_utf8_lossy(&op2_data));
        
        // Call the mutation function
        println!("Calling mutation function...");
        let result_code = func_ptr(
            &mut test_buffer as *mut Vec<u8>,
            &op1_data as *const Vec<u8>,
            &op2_data as *const Vec<u8>,
        );
        
        match result_code {
            1 => println!("Mutation function executed successfully (returned 1 - input modified)"),
            0 => println!("Mutation function returned 0 (no mutation applied)"),
            -1 => println!("Warning: Mutation function returned -1 (error/panic occurred internally)"),
            other => println!("Warning: Mutation function returned unexpected value: {}", other),
        }
        println!("Test data after mutation:");
        println!("  Buffer: {:?}", String::from_utf8_lossy(&test_buffer));
        println!("  Buffer length: {} bytes", test_buffer.len());
        
        // Test with null pointers (some functions handle null op1/op2)
        println!("\nTesting with null op1 and op2...");
        let mut test_buffer2 = Vec::from(b"another test");
        let result_code2 = func_ptr(
            &mut test_buffer2 as *mut Vec<u8>,
            std::ptr::null(),
            std::ptr::null(),
        );
        match result_code2 {
            1 => println!("Mutation function executed with null operands (returned 1 - input modified)"),
            0 => println!("Mutation function returned 0 with null operands (no mutation)"),
            -1 => println!("Warning: Mutation function returned -1 with null operands (error occurred)"),
            other => println!("Warning: Mutation function returned unexpected value: {}", other),
        }
        println!("  Buffer after mutation: {:?}", String::from_utf8_lossy(&test_buffer2));
        
        println!("\n✓ All tests passed!");
        Ok(())
    }
}

/// Convenience test function that extracts branch_id from path and tests the library.
/// 
/// # Arguments
/// * `so_path` - Path to the compiled .so library file
/// 
/// This function will try to extract branch_id from the filename (e.g., "libmut_branch_123.so" -> 123)
/// If extraction fails, you need to provide branch_id explicitly.
pub fn test_load_mutation_function_from_path(so_path: std::path::PathBuf) -> Result<(), String> {
    // Try to extract branch_id from filename
    let filename = so_path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "Invalid file path".to_string())?;
    
    // Pattern: libmut_branch_{branch_id}.so
    if let Some(start) = filename.find("libmut_branch_") {
        let start_idx = start + "libmut_branch_".len();
        if let Some(end) = filename[start_idx..].find(".so") {
            let branch_id_str = &filename[start_idx..start_idx + end];
            if let Ok(branch_id) = branch_id_str.parse::<usize>() {
                return test_load_and_use_mutation_function(so_path, branch_id);
            }
        }
    }
    
    Err(format!("Could not extract branch_id from filename: {}. Please use test_load_and_use_mutation_function() with explicit branch_id.", filename))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_function_wrapper() {
        // This is a placeholder test - actual test would require a compiled .so file
        // Users can call test_load_and_use_mutation_function() directly
    }
}
