use super::*;
use std::rc::Rc;
use std::cell::RefCell;
use crate::command;
use crate::fuzz_type::FuzzType;

pub struct SearchServer {
    rng: ThreadRng,
    afl: Rc<RefCell<AFLFuzz> >,
    taint: Rc<RefCell<TaintFuzz> >,
    exploit: Rc<RefCell<ExploitFuzz> >,
}

impl SearchServer {
    pub fn new(cmd: &command::CommandOpt,) -> Self {

        Self {
            rng: rand::thread_rng(),
            afl: Rc::new(RefCell::new(AFLFuzz::new(cmd.scheduled_mutation, cmd.havoc_div))),
            taint: Rc::new(RefCell::new(TaintFuzz::new(cmd.havoc_div, cmd.use_llm))),
            exploit: Rc::new(RefCell::new(ExploitFuzz::new())),
        }
        
    }

    pub fn mutate(&mut self, handler: &mut SearchHandler) {

        if handler.buf.len() == 0 {
            return;
        }

        // ExploitFuzz: length and const-value probes
        handler.executor.local_stats.register(FuzzType::ExploitFuzz);
        self.exploit.borrow_mut().run(handler);
        handler.executor.update_log();

        // TaintFuzz
        /* For TaintFuzz, we register LenFuzz and DirectCopyFuzz inside. */
        self.taint.borrow_mut().run(handler, &mut self.rng);

        // AFLFuzz
        handler.executor.local_stats.register(FuzzType::AFLFuzz);
        self.afl.borrow_mut().run(handler, &mut self.rng);
        handler.executor.update_log();
    }
}