use clap::{Arg, ArgAction, Command, value_parser};
use bulbasaur::fuzz_main;

fn main() {
    let matches = Command::new("bulbasaur_fuzzer")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Bulbasaur is a branch-guided fuzzer that uses Agent-generated mutators to solve hard branch constraints.")
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
        .arg(
            Arg::new("bind")
                .short('b')
                .long("bind")
                .value_name("BIND")
                .help("Bind Angora to cores starting from the id specified. We assume all cores after the specified core are free. If the cores specified are not enough, we won't bind at all.")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("thread_jobs")
                .short('j')
                .long("jobs")
                .value_name("JOB")
                .value_parser(value_parser!(usize))
                .help("Sets the number of thread jobs, default is 1"),
        )
        .arg(
            Arg::new("scheduled_mutation")
                .short('s')
                .long("scheduled_mutation")
                .help("Schedule the mutators and positions by MAB algorithm.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("x")
                .short('x')
                .long("dict")
                .value_name("DICT")
                .help("Extra dictionary path (can be used multiple times)")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("llm_port")
                .short('p')
                .long("llm_port")
                .value_name("PORT")
                .help("Port for the Agent bridge server.")
                .value_parser(clap::value_parser!(u16)),
        )
        .get_matches();

    fuzz_main(
        matches.get_one::<String>("input_dir").unwrap(),
        matches.get_one::<String>("output_dir").unwrap(),
        matches.get_many::<String>("pargs").unwrap().cloned().collect(),
        matches.get_one::<usize>("bind").copied(),
        *matches.get_one::<usize>("thread_jobs").unwrap_or(&1),
        *matches
            .get_one::<u64>("memory_limit")
            .unwrap_or(&bulbasaur_common::config::MEM_LIMIT),
        *matches
            .get_one::<u64>("time_limit")
            .unwrap_or(&bulbasaur_common::config::TIME_LIMIT),
        matches.get_flag("scheduled_mutation"),
        matches.get_one::<String>("full_target").expect("Missing full target"),
        matches.get_one::<String>("trace_target").expect("Missing trace target"),
        matches
            .get_many::<String>("x")
            .map(|vals| vals.map(|s| s.as_str()).collect::<Vec<&str>>())
          .unwrap_or_else(Vec::new),
        *matches.get_one::<u16>("llm_port").unwrap_or(&0),
    );
}
