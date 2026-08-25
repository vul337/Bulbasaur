use crate::command::CommandOpt;
use bulbasaur_common::defs;
use memmap;
use std::{fs::File, io::prelude::*, path::Path, env};
use twoway;

static CHECK_CRASH_MSG: &str = r#"
If your system is configured to send core dump, there will be an
extended delay after the program crash, which might makes crash to
misinterpreted as timeouts.
You can modify /proc/sys/kernel/core_pattern to disable it by:
# echo core | sudo tee /proc/sys/kernel/core_pattern
"#;

static CORE_PATTERN_FILE: &str = "/proc/sys/kernel/core_pattern";

fn check_crash_handling() {
    let mut f = File::open(CORE_PATTERN_FILE).unwrap();
    let mut buffer = String::new();
    f.read_to_string(&mut buffer).unwrap();
    // if buffer.trim() != "core" {
    if buffer.starts_with('|') {
        warn!("{}", CHECK_CRASH_MSG);
    }
}

fn mmap_file(target: &str) -> memmap::Mmap {
    let file = File::open(target).expect("Unable to open file");
    unsafe {
        memmap::MmapOptions::new()
            .map(&file)
            .expect("unable to mmap file")
    }
}

fn containt_string(f_data: &memmap::Mmap, s: &str) -> bool {
    twoway::find_bytes(&f_data[..], s.as_bytes()).is_some()
}

pub fn check_binary(target: &str) -> (bool, bool, bool) {
    let (mut uses_asan, mut persistent_mode, mut deferred_mode) = (false, false, false);
    let f_data = mmap_file(target);

    if f_data.len() < 4 {
        error!("File too small to be a valid ELF file: {}", target);
        panic!();
    }

    if f_data[0] != 0x7f || &f_data[1..4] != b"ELF" {
        error!("Not a valid ELF file: {}", target);
        panic!();
    }

    if !containt_string(&f_data, defs::TRACE_SHM_ENV_VAR) {
        error!("Target binary is not instrumented correctly, please check it!");
        panic!()
    }

    if containt_string(&f_data, "__asan_init") ||
       containt_string(&f_data, "__msan_init") ||
       containt_string(&f_data, "__lsan_init") {
        uses_asan = true;
    }

    if containt_string(&f_data, defs::PERSIST_SIG) {
        info!("Persistent mode binary detected.");
        env::set_var(defs::PERSIST_ENV_VAR, "1");
        persistent_mode = true;
    }

    if containt_string(&f_data, defs::DEFER_SIG) {
        info!("Deferred forkserver binary detected.");
        env::set_var(defs::DEFER_ENV_VAR, "1");
        deferred_mode = true;
    }

    (uses_asan, persistent_mode, deferred_mode)
}

fn check_io_dir(in_dir: &str, out_dir: &str) {
    let in_dir_p = Path::new(in_dir);
    let out_dir_p = Path::new(out_dir);

    if in_dir == "-" {
        if !out_dir_p.exists() {
            panic!("Original output directory is required to resume fuzzing.");
        }
    } else {
        if !in_dir_p.exists() || !in_dir_p.is_dir() {
            panic!("Input dir does not exist or is not a directory!");
        }
    }
}

pub fn check_dep(in_dir: &str, out_dir: &str, cmd: &CommandOpt) {
    check_io_dir(in_dir, out_dir);
    check_crash_handling();
}
