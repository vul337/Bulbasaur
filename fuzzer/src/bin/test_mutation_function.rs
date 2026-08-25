/// Test program to load and test a mutation function library.
/// 
/// Usage:
///   cargo run --bin test_mutation_function -- <so_path> [branch_id]
/// 
/// Examples:
///   cargo run --bin test_mutation_function -- /path/to/libmut_branch_378.so 378
///   cargo run --bin test_mutation_function -- /path/to/libmut_branch_378.so
///     (branch_id will be extracted from filename)
use std::env;
use std::path::PathBuf;
use bulbasaur::llm_loop;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <so_path> [branch_id]", args[0]);
        eprintln!("  so_path: Path to the compiled .so library file");
        eprintln!("  branch_id: Optional branch ID (will be extracted from filename if not provided)");
        eprintln!("\nExamples:");
        eprintln!("  {} /path/to/libmut_branch_378.so 378", args[0]);
        eprintln!("  {} /path/to/libmut_branch_378.so", args[0]);
        std::process::exit(1);
    }
    
    let so_path = PathBuf::from(&args[1]);
    
    let result = if args.len() >= 3 {
        // Use provided branch_id
        let branch_id: usize = args[2].parse().expect("branch_id must be a number");
        llm_loop::test_load_and_use_mutation_function(so_path, branch_id)
    } else {
        // Try to extract branch_id from filename
        llm_loop::test_load_mutation_function_from_path(so_path)
    };
    
    match result {
        Ok(()) => {
            println!("\n✓ Test completed successfully!");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("\n✗ Test failed: {}", e);
            std::process::exit(1);
        }
    }
}
