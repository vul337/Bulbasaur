/// AFL havoc mutation stage.
///
/// When `scheduled_mutation` is false (default), runs standard havoc + splice.
/// When `scheduled_mutation` is true, uses a UCB-based operator/position scheduler
/// (`afl_mutation_scheduled`) — enabled via `--scheduled_mutation` flag but not
/// recommended; field benchmarks show negligible benefit.

use crate::depot::SeedInfo;

use super::*;
use rand::{self, Rng};
use std::collections::HashMap;
use rand::distributions::WeightedIndex;
use bulbasaur_common::config::POSITION_NUM;

pub struct AFLFuzz {
    run_ratio: usize,
    tmp_buf: Vec<u8>,
    mutators: Vec<AFLMutator>,
    mutators_usage_cnt: HashMap<AFLMutator, usize>, // Record the mutators used.
    mutators_value: HashMap<AFLMutator, usize>, // Mutators value according to the result.
    mutators_weight: Option<WeightedIndex<f64>>, // Mutators weight calcualted by UCB.
    positions_usage_cnt: Vec<usize>, // Record the mutation positions used.
    positions_value: Vec<usize>,
    positions_weight:  Option<WeightedIndex<f64>>,
    total_usage_cnt: usize,
    scheduled_mutation: bool,
    havoc_div: usize,
}

impl AFLFuzz {
    pub fn new(scheduled_mutation: bool, havoc_div: usize) -> Self {

        // We use all mutation operators. 
        // TODO: Note that AFLpp uses fixed operator probabilities for mutation efficiency.
        let mutators = Vec::from([
            AFLMutator::BitFilp,
            AFLMutator::Int8,
            AFLMutator::Int16,
            AFLMutator::Int16Be,
            AFLMutator::Int32,
            AFLMutator::Int32Be,
            AFLMutator::Arith8Sub,
            AFLMutator::Arith8Add,
            AFLMutator::Arith16Sub,
            AFLMutator::Arith16SubBe,
            AFLMutator::Arith16Add,
            AFLMutator::Arith16AddBe,
            AFLMutator::Arith32Add,
            AFLMutator::Arith32AddBe,
            AFLMutator::Arith32Sub,
            AFLMutator::Arith32SubBe,
            AFLMutator::Rand8,
            AFLMutator::CloneCopy,
            AFLMutator::CloneFixed,
            AFLMutator::OverWriteCopy,
            AFLMutator::OverWriteFixed,
            AFLMutator::ByteAdd,
            AFLMutator::ByteSub,
            AFLMutator::BitFilp8,
            AFLMutator::Switch,
            AFLMutator::Del,
            AFLMutator::Shuffle,
            AFLMutator::DelOne,
            AFLMutator::InsertOne,
            AFLMutator::AsciiNum,
            AFLMutator::InsertAsciiNum,
            AFLMutator::SpliceOverwrite,
            AFLMutator::SpliceInsert,
            AFLMutator::TraceCmpData,
            AFLMutator::ExtraInsert,
            AFLMutator::ExtraOverwrite,
            AFLMutator::ConstStrcmpInsert,
            AFLMutator::ConstStrcmpOverwrite,
            AFLMutator::ConstCmpDataBe,
            AFLMutator::ConstCmpData,
        ]);

        let mutators_usage_cnt = mutators.iter().cloned().map(|m| (m, 1)).collect();
        let mutators_value = mutators.iter().cloned().map(|m| (m, 1)).collect();

        Self {
            run_ratio: 0,
            tmp_buf: Vec::new(),
            mutators,
            mutators_usage_cnt,
            mutators_value,
            mutators_weight: Option::None,
            positions_usage_cnt: vec!(1; POSITION_NUM),
            positions_value: vec!(1; POSITION_NUM),
            positions_weight: Option::None,
            total_usage_cnt: 1,
            scheduled_mutation,
            havoc_div,
        }
    }

    pub fn run<T: Rng>(&mut self, handler: &mut SearchHandler, rng: &mut T) {

        self.run_ratio = handler.calculate_score();

        if self.scheduled_mutation {
            self.afl_mutation_scheduled(handler, rng);
        } else {
            self.afl_mutation(handler, rng);
        }

    }

    // Std havoc stage.
    fn afl_mutation<T: Rng>(&mut self, handler: &mut SearchHandler, rng: &mut T) {

        let max_stacking = 1 << (1 + rng.gen_range(0..config::HAVOC_STACK_POW2));

        // Current exec count.
        handler.exec_count = 0;
        // Initial maximum execution counts
        handler.initial_max_execs = ((config::MAX_HAVOC_TIMES * 
                                self.run_ratio /
                                self.havoc_div) >>
                                8).into();
        // Final maximum execution counts
        handler.final_max_execs = ((config::MAX_HAVOC_TIMES * 
                                        config::HAVOC_MAX_MULT * 100 / 
                                        self.havoc_div) >> 
                                        8).into();
        // Skip flag
        handler.skip = false;

        loop {
            if handler.is_stopped_or_skip() {
                break;
            }

            let mut buf = handler.buf.clone();
            self.havoc_mutation(&mut buf, handler, max_stacking, rng);
            handler.exec_count += 1;

            handler.execute(&buf, SeedInfo::default());
        }

        // Splice stage.
        for _ in 0..config::MAX_SPLICE_CYCLES {
            if let Some(splice_input) = self.splice(handler, handler.seed_info.seed_id) {

                handler.exec_count = 0;
                handler.initial_max_execs = ((config::MAX_SPLICE_TIMES * 
                                        self.run_ratio / 
                                        self.havoc_div) >> 
                                        8).into();
                handler.final_max_execs = ((config::MAX_SPLICE_TIMES * 
                                                config::HAVOC_MAX_MULT * 100 / 
                                                self.havoc_div) >> 
                                                8).into();
                handler.skip = false;
                
                loop {
                    if handler.is_stopped_or_skip() {
                        break;
                    }
                    let mut buf = splice_input.clone();
                    self.havoc_mutation(&mut buf, handler, max_stacking, rng);
                    handler.exec_count += 1;
                    handler.execute(&buf, SeedInfo::default());
                }

            } else {
                continue;
            }
        }
    }

    // Scheduled havoc stage. It it not recommended to enable it.
    fn afl_mutation_scheduled<T: Rng>(&mut self, handler: &mut SearchHandler, rng: &mut T) {
        let max_stacking = 1 << (1 + rng.gen_range(0..config::HAVOC_STACK_POW2));

        self.mutators_weight = Some(self.calculate_mutators_weight());
        self.positions_weight = Some(self.calculate_positions_weight());

        handler.exec_count = 0;

        handler.initial_max_execs = ((config::MAX_HAVOC_TIMES * 
            self.run_ratio /
            self.havoc_div) >>
            8).into();

        handler.final_max_execs = ((config::MAX_HAVOC_TIMES * 
            config::HAVOC_MAX_MULT * 100 / 
            self.havoc_div) >> 
            8).into();

        handler.skip = false;

        loop {
            if handler.is_stopped_or_skip() {
                break;
            }
            let mut buf = handler.buf.clone();
            let (now_mutator_cnt, now_position_cnt) = self.havoc_mutation_scheduled(&mut buf, handler, max_stacking, rng);
            handler.exec_count += 1;
            handler.execute(&buf, SeedInfo::default());
            self.update_ucb_value(handler, now_mutator_cnt, now_position_cnt)
        }

        // Splice stage
        for _ in 0..config::MAX_SPLICE_CYCLES {
            if let Some(splice_input) = self.splice(handler, handler.seed_info.seed_id) {
                handler.exec_count = 0;
                handler.initial_max_execs = ((config::MAX_SPLICE_TIMES * 
                                        self.run_ratio / 
                                        self.havoc_div) >> 
                                        8).into();
                handler.final_max_execs = ((config::MAX_SPLICE_TIMES * 
                                                config::HAVOC_MAX_MULT * 100 / 
                                                self.havoc_div) >> 
                                                8).into();
                handler.skip = false;
                
                loop {
                    if handler.is_stopped_or_skip() {
                        break;
                    }
                    let mut buf = splice_input.clone();
                    let (now_mutator_cnt, now_position_cnt) = self.havoc_mutation_scheduled(&mut buf, handler, max_stacking, rng);
                    handler.exec_count += 1;
                    handler.execute(&buf, SeedInfo::default());
                    self.update_ucb_value(handler, now_mutator_cnt, now_position_cnt)
                }

            } else {
                continue;
            }
        }
    }

    fn locate_diffs(buf1: &Vec<u8>, buf2: &Vec<u8>, len: usize) -> (Option<usize>, Option<usize>) {
        let mut first_loc = None;
        let mut last_loc = None;

        for i in 0..len {
            if buf1[i] != buf2[i] {
                if first_loc.is_none() {
                    first_loc = Some(i);
                }
                last_loc = Some(i);
            }
        }

        (first_loc, last_loc)
    }

    fn splice_two_vec(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Option<Vec<u8>> {
        let len = std::cmp::min(buf1.len(), buf2.len());
        if len < 2 {
            return None;
        }
        let (f_loc, l_loc) = Self::locate_diffs(buf1, buf2, len);
        if f_loc.is_none() || l_loc.is_none() {
            return None;
        }
        let f_loc = f_loc.unwrap();
        let l_loc = l_loc.unwrap();
        if f_loc == l_loc {
            return None;
        }

        let split_at = f_loc + rand::random::<usize>() % (l_loc - f_loc);
        Some([&buf1[..split_at], &buf2[split_at..]].concat())
    }


    fn splice(&mut self, handler: &mut SearchHandler, now_id: usize) -> Option<Vec<u8>> {
        let buf1 = handler.buf.clone();
        let buf2 = handler.executor.random_splice_input_buf(now_id);
        Self::splice_two_vec(&buf1, &buf2)
    }

    // Generate one testcase by std havoc.
    fn havoc_mutation<T: Rng>(
        &mut self, 
        buf: &mut Vec<u8>, 
        handler: &mut SearchHandler,
        max_stacking: usize, 
        rng: &mut T
    ) {
        let use_stacking = 1 + rng.gen_range(0..max_stacking);

        for _ in 0..use_stacking {
            let mutator = self.mutators[rng.gen_range(0..self.mutators.len())];
            match mutator {
                AFLMutator::BitFilp => {
                    afl_mutators::mut_bitflip(buf, rng);
                }
                AFLMutator::Int8 => {
                    afl_mutators::mut_interesting8(buf, rng);
                }
                AFLMutator::Int16 => {
                    afl_mutators::mut_interesting16(buf, rng);
                }
                AFLMutator::Int16Be => {
                    afl_mutators::mut_interesting16_be(buf, rng);
                }
                AFLMutator::Int32 => {
                    afl_mutators::mut_interesting32(buf, rng);
                }
                AFLMutator::Int32Be => {
                    afl_mutators::mut_interesting32_be(buf, rng);
                }
                AFLMutator::Arith8Sub => {
                    afl_mutators::mut_arith8_sub(buf, rng);
                }
                AFLMutator::Arith8Add => {
                    afl_mutators::mut_arith8_add(buf, rng);
                }
                AFLMutator::Arith16Sub => {
                    afl_mutators::mut_arith16_sub(buf, rng);
                }
                AFLMutator::Arith16SubBe => {
                    afl_mutators::mut_arith16_sub_be(buf, rng);
                }
                AFLMutator::Arith16Add => {
                    afl_mutators::mut_arith16_add(buf, rng);
                }
                AFLMutator::Arith16AddBe => {
                    afl_mutators::mut_arith16_add_be(buf, rng);
                }
                AFLMutator::Arith32Add => {
                    afl_mutators::mut_arith32_add(buf, rng);
                }
                AFLMutator::Arith32AddBe => {
                    afl_mutators::mut_arith32_add_be(buf, rng);
                }
                AFLMutator::Arith32Sub => {
                    afl_mutators::mut_arith32_sub(buf, rng);
                }
                AFLMutator::Arith32SubBe => {
                    afl_mutators::mut_arith32_sub_be(buf, rng);
                }
                AFLMutator::Rand8 => {
                    afl_mutators::mut_rand8(buf, rng);
                }
                AFLMutator::CloneCopy => {
                    afl_mutators::mut_clone_copy(buf, rng, &mut self.tmp_buf);
                }
                AFLMutator::CloneFixed => {
                    afl_mutators::mut_clone_fixed(buf, rng, &mut self.tmp_buf);
                }
                AFLMutator::OverWriteCopy => {
                    afl_mutators::mut_overwrite_copy(buf, rng);
                }
                AFLMutator::OverWriteFixed => {
                    afl_mutators::mut_overwrite_fixed(buf, rng);
                }
                AFLMutator::ByteAdd => {
                    afl_mutators::mut_byte_add(buf, rng);
                }
                AFLMutator::ByteSub => {
                    afl_mutators::mut_byte_sub(buf, rng);
                }
                AFLMutator::BitFilp8 => {
                    afl_mutators::mut_bitflip8(buf, rng);
                }
                AFLMutator::Switch => {
                    afl_mutators::mut_switch(buf, rng, &mut self.tmp_buf);
                }
                AFLMutator::Del => {
                    afl_mutators::mut_del(buf, rng);
                }
                AFLMutator::Shuffle => {
                    afl_mutators::mut_shuffle(buf, rng);
                }
                AFLMutator::DelOne => {
                    afl_mutators::mut_del_one(buf, rng);
                }
                AFLMutator::InsertOne => {
                    afl_mutators::mut_insert_one(buf, rng);
                }
                AFLMutator::AsciiNum => {
                    afl_mutators::mut_ascii_num(buf, rng, &mut self.tmp_buf);
                }
                AFLMutator::InsertAsciiNum => {
                    afl_mutators::mut_insert_ascii_num(buf, rng);
                }
                AFLMutator::SpliceOverwrite => {
                    afl_mutators::mut_splice_overwrite(buf, handler, rng);
                }
                AFLMutator::SpliceInsert => {
                    afl_mutators::mut_splice_insert(buf, handler, rng, &mut self.tmp_buf);
                }
                AFLMutator::TraceCmpData => {
                    afl_mutators::mut_trace_cmp_data(buf, handler, rng);
                }
                AFLMutator::ExtraInsert => {
                    afl_mutators::mut_extra_insert(buf, handler, rng);
                }
                AFLMutator::ExtraOverwrite => {
                    afl_mutators::mut_extra_overwrite(buf, handler, rng);
                }
                AFLMutator::ConstCmpData => {
                    afl_mutators::mut_const_cmp_data(buf, handler, rng);
                }
                AFLMutator::ConstCmpDataBe => {
                    afl_mutators::mut_const_cmp_data_be(buf, handler, rng);
                }
                AFLMutator::ConstStrcmpInsert => {
                    afl_mutators::mut_const_strcmp_insert(buf, handler, rng);
                }
                AFLMutator::ConstStrcmpOverwrite => {
                    afl_mutators::mut_const_strcmp_overwrite(buf, handler, rng);
                }
            }
        }
    }

    // Generate one testcase by scheduled havoc.
    fn havoc_mutation_scheduled<T: Rng>(
        &mut self, 
        buf: &mut Vec<u8>, 
        handler: &mut SearchHandler,
        max_stacking: usize, 
        rng: &mut T
    ) -> (HashMap<AFLMutator, usize>, Vec<usize>) {
        let use_stacking = 1 + rng.gen_range(0..max_stacking);

        let mut now_mutator_cnt = HashMap::<AFLMutator, usize>::new();
        let mut now_position_cnt = vec![0; POSITION_NUM];

        for _ in 0..use_stacking {
            let mutator = self.mutators[self.mutators_weight.as_ref().expect("mutators_weight is not initialized.").sample(rng)];

            // Count the number of mutators used.
            now_mutator_cnt.entry(mutator).and_modify(|c| *c += 1).or_insert(1);
            self.mutators_usage_cnt.entry(mutator).and_modify(|c| *c += 1).or_insert(1);

            // Count the number of position used.
            let position = self.positions_weight.as_ref().expect("mutators_weight is not initialized.").sample(rng);
            now_position_cnt[position] += 1;
            self.positions_usage_cnt[position] += 1;

            self.total_usage_cnt += 1;

            match mutator {
                AFLMutator::BitFilp => {
                    afl_mutators_scheduled::mut_bitflip(buf, rng, position);
                }
                AFLMutator::Int8 => {
                    afl_mutators_scheduled::mut_interesting8(buf, rng, position);
                }
                AFLMutator::Int16 => {
                    afl_mutators_scheduled::mut_interesting16(buf, rng, position);
                }
                AFLMutator::Int16Be => {
                    afl_mutators_scheduled::mut_interesting16_be(buf, rng, position);
                }
                AFLMutator::Int32 => {
                    afl_mutators_scheduled::mut_interesting32(buf, rng, position);
                }
                AFLMutator::Int32Be => {
                    afl_mutators_scheduled::mut_interesting32_be(buf, rng, position);
                }
                AFLMutator::Arith8Sub => {
                    afl_mutators_scheduled::mut_arith8_sub(buf, rng, position);
                }
                AFLMutator::Arith8Add => {
                    afl_mutators_scheduled::mut_arith8_add(buf, rng, position);
                }
                AFLMutator::Arith16Sub => {
                    afl_mutators_scheduled::mut_arith16_sub(buf, rng, position);
                }
                AFLMutator::Arith16SubBe => {
                    afl_mutators_scheduled::mut_arith16_sub_be(buf, rng, position);
                }
                AFLMutator::Arith16Add => {
                    afl_mutators_scheduled::mut_arith16_add(buf, rng, position);
                }
                AFLMutator::Arith16AddBe => {
                    afl_mutators_scheduled::mut_arith16_add_be(buf, rng, position);
                }
                AFLMutator::Arith32Add => {
                    afl_mutators_scheduled::mut_arith32_add(buf, rng, position);
                }
                AFLMutator::Arith32AddBe => {
                    afl_mutators_scheduled::mut_arith32_add_be(buf, rng, position);
                }
                AFLMutator::Arith32Sub => {
                    afl_mutators_scheduled::mut_arith32_sub(buf, rng, position);
                }
                AFLMutator::Arith32SubBe => {
                    afl_mutators_scheduled::mut_arith32_sub_be(buf, rng, position);
                }
                AFLMutator::Rand8 => {
                    afl_mutators_scheduled::mut_rand8(buf, rng, position);
                }
                AFLMutator::CloneCopy => {
                    afl_mutators_scheduled::mut_clone_copy(buf, rng, &mut self.tmp_buf, position);
                }
                AFLMutator::CloneFixed => {
                    afl_mutators_scheduled::mut_clone_fixed(buf, rng, &mut self.tmp_buf, position);
                }
                AFLMutator::OverWriteCopy => {
                    afl_mutators_scheduled::mut_overwrite_copy(buf, rng, position);
                }
                AFLMutator::OverWriteFixed => {
                    afl_mutators_scheduled::mut_overwrite_fixed(buf, rng, position);
                }
                AFLMutator::ByteAdd => {
                    afl_mutators_scheduled::mut_byte_add(buf, rng, position);
                }
                AFLMutator::ByteSub => {
                    afl_mutators_scheduled::mut_byte_sub(buf, rng, position);
                }
                AFLMutator::BitFilp8 => {
                    afl_mutators_scheduled::mut_bitflip8(buf, rng, position);
                }
                AFLMutator::Switch => {
                    afl_mutators_scheduled::mut_switch(buf, rng, &mut self.tmp_buf, position);
                }
                AFLMutator::Del => {
                    afl_mutators_scheduled::mut_del(buf, rng, position);
                }
                AFLMutator::Shuffle => {
                    afl_mutators_scheduled::mut_shuffle(buf, rng, position);
                }
                AFLMutator::DelOne => {
                    afl_mutators_scheduled::mut_del_one(buf, rng, position);
                }
                AFLMutator::InsertOne => {
                    afl_mutators_scheduled::mut_insert_one(buf, rng, position);
                }
                AFLMutator::AsciiNum => {
                    afl_mutators_scheduled::mut_ascii_num(buf, rng, &mut self.tmp_buf, position);
                }
                AFLMutator::InsertAsciiNum => {
                    afl_mutators_scheduled::mut_insert_ascii_num(buf, rng, position);
                }
                AFLMutator::SpliceOverwrite => {
                    afl_mutators_scheduled::mut_splice_overwrite(buf, handler, rng, position);
                }
                AFLMutator::SpliceInsert => {
                    afl_mutators_scheduled::mut_splice_insert(buf, handler, rng, &mut self.tmp_buf, position);
                }
                AFLMutator::TraceCmpData => {
                    afl_mutators_scheduled::mut_trace_cmp_data(buf, handler, rng, position);
                }
                AFLMutator::ExtraInsert => {
                    afl_mutators_scheduled::mut_extra_insert(buf, handler, rng, position);
                }
                AFLMutator::ExtraOverwrite => {
                    afl_mutators_scheduled::mut_extra_overwrite(buf, handler, rng, position);
                }
                AFLMutator::ConstCmpData => {
                    afl_mutators_scheduled::mut_const_cmp_data(buf, handler, rng, position);
                }
                AFLMutator::ConstCmpDataBe => {
                    afl_mutators_scheduled::mut_const_cmp_data_be(buf, handler, rng, position);
                }
                AFLMutator::ConstStrcmpInsert => {
                    afl_mutators_scheduled::mut_const_strcmp_insert(buf, handler, rng, position);
                }
                AFLMutator::ConstStrcmpOverwrite => {
                    afl_mutators_scheduled::mut_const_strcmp_overwrite(buf, handler, rng, position);
                }
            }
        };
        (now_mutator_cnt, now_position_cnt)
    }

    fn update_ucb_value(&mut self, handler: &mut SearchHandler, 
                            now_mutator_cnt: HashMap<AFLMutator, usize>,
                            now_position_cnt: Vec<usize>) {
        let mut inc_value = 0;
        // Increase value according to different feedback.
        // Value is used to calculate weight.
        if handler.executor.has_new_path {
            inc_value += 5;
        }
        if handler.executor.has_new_edge {
            inc_value += 10;
        }
        if handler.executor.has_higher_match {
            inc_value += 5;
        }
        if inc_value == 0 {
            return;
        }
        // Update mutators
        for (key, value) in &now_mutator_cnt {
            assert!(*value != 0);
            self.mutators_value.entry(*key).and_modify(|c| *c += inc_value * value);
        }
        // Update positions
        for i in 0..now_position_cnt.len() {
            self.positions_value[i] += inc_value * now_position_cnt[i];
        }
    }

    // Calculate mutators weight according UCB algorithm.
    fn calculate_mutators_weight(&self) -> WeightedIndex<f64> {
        let mut mutators_weight = Vec::<f64>::new();
        mutators_weight.resize(self.mutators.len(), 0.0);
        for i in 0..self.mutators.len() {

            // score_i = value_i / total_i + sqrt(2 * ln(total) / total_i)
            mutators_weight[i] = self.mutators_value[&self.mutators[i]] as f64 / 
                                self.mutators_usage_cnt[&self.mutators[i]] as f64 +
                                (2.0 * (self.total_usage_cnt as f64).ln() / 
                                self.mutators_usage_cnt[&self.mutators[i]] as f64).sqrt();

        }
        debug!("mutators weight: {:#?}", mutators_weight);
        WeightedIndex::new(&mutators_weight).unwrap()
    }

    // Calculate positions weight according UCB algorithm
    fn calculate_positions_weight(&self) -> WeightedIndex<f64> {
        let mut positions_weight = Vec::<f64>::new();
        positions_weight.resize(POSITION_NUM, 0.0);
        for i in 0..POSITION_NUM {

            // score_i = value_i / total_i + sqrt(2 * ln(total) / total_i)
            positions_weight[i] = self.positions_value[i] as f64 / 
                                self.positions_usage_cnt[i] as f64 +
                                (2.0 * (self.total_usage_cnt as f64).ln() / 
                                self.positions_usage_cnt[i] as f64).sqrt();

        }
        debug!("positions weight: {:#?}", positions_weight);
        WeightedIndex::new(&positions_weight).unwrap()
    }

}
