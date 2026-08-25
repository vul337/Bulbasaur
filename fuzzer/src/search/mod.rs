use crate::{
    // cond_stmt::CondStmt,
    executor::{Executor, StatusType},
};
use bulbasaur_common::config;
use rand::prelude::*;
use std::{
    self,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    ptr,
};

mod handler;
pub use self::handler::SearchHandler;
//Other cases of special offsets
pub mod afl;
pub use self::afl::AFLFuzz;

pub mod taint;
pub use self::taint::TaintFuzz;

// pub mod trim;

mod afl_mutators;
use afl_mutators::AFLMutator;

mod afl_mutators_scheduled;

pub mod search_server;
pub use self::search_server::SearchServer;

mod interesting_value;
use interesting_value::*;

mod exploit;
use exploit::ExploitFuzz;