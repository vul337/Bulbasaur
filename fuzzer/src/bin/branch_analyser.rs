use clap::{Arg, Command};
use bulbasaur::branch_analyse_main::branch_analyse_main;

fn main() {
    let matches = Command::new("branch_analyser")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Branch Analyser analyzes the branch coverage of a given corpus and saves the results to the specified output directory.")
        .arg(
            Arg::new("input_dir")
                .short('i')
                .long("input")
                .value_name("DIR")
                .help("Path to the corpus directory containing all initial seeds.")
                .required(true),
        )
        .arg(
            Arg::new("output_dir")
                .short('o')
                .long("output")
                .value_name("DIR")
                .help("Path to the output directory.(Note the path must not exist.)")
                .required(true),
        )
        .arg(
            Arg::new("full_target")
                .short('f')
                .long("full")
                .value_name("PROM")
                .help("Target program with full mode instrumentation."),
        )
        .arg(
            Arg::new("trace_target")
                .short('t')
                .long("trace")
                .value_name("PROM")
                .help("Target program with trace mode instrumentation."),
        )
        .arg(
            Arg::new("pargs")
                .help(concat!(
                    "Targeted program with fast mode instrumentation and arguments. ",
                    "Any \"@@\" will be substituted with the input filename. ",
                    "(Note you don't need \"@@\" if the target requires inputs from stdin or shmem.)"
               ))
                .required(true)
                .num_args(1..)
                .allow_hyphen_values(true)
                .last(true),
        )
        .arg(
            Arg::new("memory_limit")
                .short('M')
                .long("memory_limit")
                .value_name("MEM")
                .help("Memory limit for programs, default is 200(MB), set 0 for unlimited memory")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("time_limit")
                .short('T')
                .long("time_limit")
                .value_name("TIME")
                .help("Time limit for programs, default is automatic timeout mode.")
                .value_parser(clap::value_parser!(u64)),
        )
        .get_matches();

    branch_analyse_main(
        matches.get_one::<String>("input_dir").unwrap(),
        matches.get_one::<String>("output_dir").unwrap(),
        matches.get_many::<String>("pargs").unwrap().cloned().collect(),
        *matches
            .get_one::<u64>("memory_limit")
            .unwrap_or(&bulbasaur_common::config::MEM_LIMIT),
        *matches
            .get_one::<u64>("time_limit")
            .unwrap_or(&bulbasaur_common::config::TIME_LIMIT),
        matches.get_one::<String>("full_target").expect("Missing full target"),
        matches.get_one::<String>("trace_target").expect("Missing trace target"),
    );

}