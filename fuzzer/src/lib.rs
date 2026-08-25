#![cfg_attr(feature = "unstable", feature(core_intrinsics))]

#[macro_use]
extern crate log;
#[macro_use]
extern crate derive_more;

pub mod branches;
mod depot;
pub mod executor;
mod search;
mod stats;
mod parse_raw_section;

mod fuzz_loop;
mod fuzz_main;
mod fuzz_type;
mod extras;
pub mod llm_loop;

mod bind_cpu;
mod check_dep;
mod command;
mod tmpfs;
pub mod branch_analyse_main;

pub use crate::fuzz_main::fuzz_main;
pub use crate::branch_analyse_main::branch_analyse_main;