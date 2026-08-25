use std::{env, fs::File, io::{BufRead, BufReader}, mem, thread::sleep, time::Duration};

// Find CPUs whose usage is below 5%.
#[cfg(target_os = "linux")]
pub fn find_free_cpus(ask_num: usize) -> Vec<usize> {
    let mut free_cpus = vec![];

    // Do not bind to CPU if DISABLE_CPU_BINDING_VAR is set.
    if env::var(bulbasaur_common::defs::DISABLE_CPU_BINDING_VAR).is_ok() {
        return free_cpus;
    }

    let usage1 = read_cpu_stats();
    sleep(Duration::from_millis(500));
    let usage2 = read_cpu_stats();

    let mut cpu_usage: Vec<f64> = vec![];

    for (u1, u2) in usage1.iter().zip(usage2.iter()) {
        let delta_total = (u2.total - u1.total) as f64;
        let delta_idle = (u2.idle - u1.idle) as f64;
        let usage = if delta_total == 0.0 {
            0.0
        } else {
            1.0 - (delta_idle / delta_total)
        };
        cpu_usage.push(usage);
    }

    for (i, &u) in cpu_usage.iter().enumerate() {
        if u < 0.05 {
            free_cpus.push(i);
        }
    }

    info!("Free Cpus (usage < 5%): {:?}", free_cpus);

    if free_cpus.len() > ask_num {
        free_cpus.truncate(ask_num);
    }

    free_cpus
}

struct CpuStat {
    idle: u64,
    total: u64,
}

// Read cpu statistics from /proc/stat.
fn read_cpu_stats() -> Vec<CpuStat> {
    let file = File::open("/proc/stat").unwrap();
    let reader = BufReader::new(file);
    let mut stats = vec![];

    for line in reader.lines() {
        if let Ok(line) = line {
            if line.starts_with("cpu") && line.chars().nth(3).unwrap_or(' ').is_digit(10) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 5 {
                    continue;
                }
                let idle: u64 = parts[4].parse().unwrap_or(0);
                let total: u64 = parts.iter()
                    .skip(1)
                    .take_while(|s| s.parse::<u64>().is_ok())
                    .map(|s| s.parse::<u64>().unwrap_or(0))
                    .sum();
                stats.push(CpuStat { idle, total });
            }
        }
    }

    stats
}

#[cfg(target_os = "linux")]
pub fn bind_thread_to_cpu_core(cid: usize) {
    unsafe {
        let mut c: libc::cpu_set_t = mem::zeroed();
        libc::CPU_ZERO(&mut c);
        libc::CPU_SET(cid, &mut c);
        if libc::sched_setaffinity(0, mem::size_of_val(&c), &c as *const libc::cpu_set_t) != 0 {
            panic!("sched_setaffinity failed");
        }
    }
}
