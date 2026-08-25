use super::*;
use std::cmp::min;
use crate::depot::SeedInfo;
use crate::branches::BranchType;
use crate::extras::{self, ExtraData};
use bulbasaur_common::trace_data;

pub struct SearchHandler<'a> {
    running: Arc<AtomicBool>,
    pub executor: &'a mut Executor,
    pub seed_info: SeedInfo,
    pub initial_max_execs: usize,
    pub final_max_execs: usize,
    pub skip: bool,
    pub buf: Vec<u8>,
    pub exec_count: usize,

    // Queue rewards.
    pub queue_rewards: (usize, usize),
    // Len Fuzz
    pub len_vec: Vec<usize>,    
    // Direct copy fuzz.
    pub cmp_data_in_direct_copy: Vec<(Vec<u8>, Vec<u8>)>, // vec(op1, op2, len)
    // IDS(TS) sampling
    pub index_to_branch_dict: Vec<usize>,

    // Const cmp data.
    pub const_cmp_data_vec: Vec<(u64, usize)>,
    pub const_strcmp_data_vec: Vec<ExtraData>,
}

impl<'a> SearchHandler<'a> {
    pub fn new(
        running: Arc<AtomicBool>,
        executor: &'a mut Executor,
        seed_info: SeedInfo,
    ) -> Self {
        assert!(seed_info.seed_id > 0);
        let buf = executor.depot.get_input_buf(seed_info.seed_id);

        Self {
            running,
            executor,
            seed_info,
            initial_max_execs: 0,
            final_max_execs: 0,
            skip: false,
            buf,
            exec_count: 0,
            queue_rewards: (0, 0),
            len_vec: Vec::new(),
            cmp_data_in_direct_copy: Vec::new(),
            index_to_branch_dict: Vec::new(),
            const_cmp_data_vec: Vec::new(),
            const_strcmp_data_vec: Vec::new(),
        }
    }

    pub fn is_stopped_or_skip(&self) -> bool {
        !self.running.load(Ordering::Relaxed) || self.skip
    }

    fn update_queue_rewards(&mut self) {
        let mut reward = 0;
        // Apply bonuses if new paths, edges, or higher match values are found.
        if self.executor.has_new_path {
            reward += 1;
        }
        if self.executor.has_new_edge {
            reward += 1;
        }
        if self.executor.has_higher_match {
            reward += 1;
        }

        if reward == 0 {
            self.queue_rewards.1 += 1;
        } else {
            self.queue_rewards.0 += reward;
        }
    }

    fn process_status(&mut self, status: StatusType) {
        // Update queue rewards each input execution.
        self.update_queue_rewards();

        match status {
            StatusType::Skip => {
                // Skip if consecutive timeous occur.
                self.skip = true;
            },
            _ => {},
        }

        // Apply bonuses if new paths, edges, or higher match values are found.
        if status == StatusType::Normal && self.executor.has_new_path && self.initial_max_execs < self.final_max_execs  {
            self.initial_max_execs = (self.initial_max_execs as f64 * config::NEW_PATH_BONUS) as usize;
        }
        if status == StatusType::Normal && self.executor.has_new_edge && self.initial_max_execs < self.final_max_execs  {
            self.initial_max_execs = (self.initial_max_execs as f64 * config::NEW_EDGE_BONUS) as usize;
        }
        if status == StatusType::Normal && self.executor.has_higher_match && self.initial_max_execs < self.final_max_execs {
            self.initial_max_execs = (self.initial_max_execs as f64 * config::GREATER_DIST_BONUS) as usize;
        }

        // Skip if execution count exceeds initial_max_execs.
        if self.exec_count > self.initial_max_execs {
            self.skip = true;
        }
    }

    // Execute one testcase.
    pub fn execute(&mut self, buf: &Vec<u8>, seed_info: SeedInfo) -> StatusType {
        let status = self.executor.run(buf, seed_info);
        self.process_status(status);
        status
    }

    pub fn execute_trace_and_load(&mut self, buf: &Vec<u8>) {
        let trace_status = self.executor.trace_testcase(buf);

        if trace_status != StatusType::Normal {
            warn!("Trace target execution encounter abnormal status: {:?}", trace_status);
            return
        }

        // let covered_branch = self.executor.get_covered_branch_of_testcase();
        let cmp_tarce_data = self.executor.branches.get_cmp_trace_copy();

        // Check.
        #[cfg(debug_assertions)]
        for (branch_id, cmp_info) in cmp_tarce_data.iter().enumerate() {
            if branch_id == 0 {
                for i in 0..config::UNIT_MAX_TRACE_CNT {
                    assert!(cmp_info.size == 0 && cmp_info.units[i].match_num == 0 && cmp_info.units[i].len == 0 &&
                            cmp_info.units[i].op1 == 0 && cmp_info.units[i].op2 == 0);
                }
                continue;
            }
            let branch_type = self.executor.branches.get_trace_branch_type(branch_id);

            if matches!(branch_type, BranchType::Cmp | BranchType::ConstCmp | BranchType::Switch) {
                for i in 0..config::UNIT_MAX_TRACE_CNT {
                    if cmp_info.units[i].match_num == 0 {
                        assert!(cmp_info.units[i].len == 0 && cmp_info.units[i].op1 == 0 && cmp_info.units[i].op2 == 0);
                    } else {
                        assert!(matches!(cmp_info.units[i].len, 1 | 2 | 4 | 8));
                    }
                }
            } else {
                // strcmp
                let strcmp_info: &trace_data::StrcmpTrace = unsafe {
                    &*(cmp_info as *const trace_data::CmpTrace as *const trace_data::StrcmpTrace)
                };

                for i in 0..config::UNIT_MAX_TRACE_CNT {
                    if strcmp_info.units[i].match_num == 0 {
                        assert!(strcmp_info.units[i].len1 == 0 && strcmp_info.units[i].len2 == 0 && strcmp_info.units[i].len3 == 0 
                                && strcmp_info.units[i].occu == 0);
                    } else {
                        assert!(strcmp_info.units[i].len1 <= 32 && strcmp_info.units[i].len2 <= 32 && strcmp_info.units[i].len3 <= 32);
                        assert!(strcmp_info.units[i].occu == 0);
                    }
                }
            }
        }

        for (branch_id, cmp_info) in cmp_tarce_data.iter().enumerate() {
            if cmp_info.units[0].match_num == 0 {
                // Debug
                #[cfg(debug_assertions)]
                for i in 1..config::UNIT_MAX_TRACE_CNT {
                    assert!(cmp_info.units[i].match_num == 0)
                }

                continue
            }

            /* 
            TODO:
                While skipping covered branches can benefit some targets,
                I think keeping all branches may perform well 
                if the fuzzer runs for a long time...
            */

            // Skip covered branch.
            // if covered_branch.contains_key(&branch_id) {
            //     continue
            // }
            
            let branch_type = self.executor.branches.get_trace_branch_type(branch_id);
            if matches!(branch_type, BranchType::Cmp | BranchType::ConstCmp | BranchType::Switch) {

                for i in 0..config::UNIT_MAX_TRACE_CNT {
                    if cmp_info.units[i].match_num == 0 {
                        break;
                    }

                    assert!(matches!(cmp_info.units[i].len, 1 | 2 | 4 | 8));

                    /* detect length in ops  */ 
                    {
                        let mut len_flag = false;
                        // op1 -> op2
                        if cmp_info.units[i].op1 == self.buf.len() as u64 {
                            if cmp_info.units[i].op2 >= 1 && cmp_info.units[i].op2 <= 2 * self.buf.len() as u64 && cmp_info.units[i].op2 <= config::MAX_INPUT_LEN as u64 {
                                self.len_vec.push(cmp_info.units[i].op2 as usize);
                            }
                            len_flag = true;
                        }
                        // op2 -> op1
                        if cmp_info.units[i].op2 == self.buf.len() as u64 {
                            if cmp_info.units[i].op1 >= 1 && cmp_info.units[i].op1 <= 2 * self.buf.len() as u64 && cmp_info.units[i].op1 <= config::MAX_INPUT_LEN as u64 {
                                self.len_vec.push(cmp_info.units[i].op1 as usize);
                            }
                            len_flag = true;
                        }
                        if len_flag {
                            continue;
                        }
                    }

                    /* Ordinary cmp data */
                    if matches!(branch_type, BranchType::ConstCmp | BranchType::Switch) {
                        self.const_cmp_data_vec.push((cmp_info.units[i].op1, cmp_info.units[i].len as usize));
                    } 

                    /* Collect branch parameter */
                    // Skip comparisons of length 1, as they match too many points in the input.
                    if cmp_info.units[i].len > 0 {
                        self.cmp_data_in_direct_copy.push(
                            (
                            cmp_info.units[i].op1.to_le_bytes()[..cmp_info.units[i].len as usize].to_vec(), 
                            cmp_info.units[i].op2.to_le_bytes()[..cmp_info.units[i].len as usize].to_vec()
                            )
                        );
                        
                        self.index_to_branch_dict.push(branch_id);
                    }
                }

            } else {
                // strcmp
                let strcmp_info: &trace_data::StrcmpTrace = unsafe {
                    &*(cmp_info as *const trace_data::CmpTrace as *const trace_data::StrcmpTrace)
                };

                for i in 0..config::UNIT_MAX_TRACE_CNT {
                    assert!(strcmp_info.units[i].len1 <= 32 && strcmp_info.units[i].len2 <= 32 && strcmp_info.units[i].len3 <= 32);
                    assert!(strcmp_info.units[i].occu == 0);

                    if strcmp_info.units[i].match_num == 0 {
                        break;
                    }

                    let op1_len = min(strcmp_info.units[i].len1, strcmp_info.units[i].len3) as usize;
                    let op1_substr = strcmp_info.units[i].op1[..op1_len].to_vec();
                    let op2_len = min(strcmp_info.units[i].len2, strcmp_info.units[i].len3) as usize;
                    let op2_substr = strcmp_info.units[i].op2[..op2_len].to_vec();

                    /* Collect branch parameter */
                    if op1_substr.len() > 0 && op2_substr.len() > 0 {
                        self.cmp_data_in_direct_copy.push((op1_substr.clone(), op2_substr.clone()));

                        self.index_to_branch_dict.push(branch_id);
                    }

                    /* Ordinary strcmp data */
                    if matches!(branch_type, BranchType::ConstStrcmp | BranchType::ConstStrcmpNonTerm) {
                        if op1_len > 0 {
                            self.const_strcmp_data_vec.push(ExtraData {
                                data: op1_substr.clone(),
                                len: op1_substr.len()
                            });
                        }
                    } else if matches!(branch_type, BranchType::Strcmp | BranchType::StrcmpNonTerm) {
                        if op1_len > 0 {
                            self.const_strcmp_data_vec.push(ExtraData {
                                data: op1_substr.clone(),
                                len: op1_substr.len()
                            });
                        }
                        if op2_len > 0 {
                            self.const_strcmp_data_vec.push(ExtraData {
                                data: op2_substr.clone(),
                                len: op2_substr.len()
                            });
                        }
                    }

                }
            }
        }

        assert!(self.cmp_data_in_direct_copy.len() == self.index_to_branch_dict.len());

        // Remove duplicates
        self.const_strcmp_data_vec.sort();
        extras::deunicode_extras(&mut self.const_strcmp_data_vec);
        extras::dedup_extras(&mut self.const_strcmp_data_vec);

        self.len_vec.sort();
        self.len_vec.dedup();
        self.const_cmp_data_vec.sort();
        self.const_cmp_data_vec.dedup();

        debug!("len size: {}, cmp data in direct copy size: {}", self.len_vec.len(), self.cmp_data_in_direct_copy.len());
    }

    pub fn get_extra_data(&self) -> &Vec<ExtraData> {
        &self.executor.depot.extras_data
    }

    pub fn calculate_score(&self) -> usize {
        let exec_time_us = self.seed_info.exec_time_us as f64;
        let avg_exec_us = self.executor.local_stats.avg_exec_time.get() as f64;

        // First, adjust score by exec time.
        let mut mutation_score  = 100;
        if exec_time_us * 0.1 > avg_exec_us {
            mutation_score = 10;
      
        } else if exec_time_us * 0.25 > avg_exec_us {
            mutation_score = 25;
      
        } else if exec_time_us * 0.5 > avg_exec_us {
            mutation_score = 50;
      
        } else if exec_time_us * 0.75 > avg_exec_us {
            mutation_score = 75;
      
        } else if exec_time_us * 4.0 < avg_exec_us {
            mutation_score = 300;
      
        } else if exec_time_us * 3.0 < avg_exec_us {
            mutation_score = 200;
      
        } else if exec_time_us * 2.0 < avg_exec_us {
            mutation_score = 150;

        }

        // Second, adjust score by edge num.
        let edge_num = self.seed_info.edge_num as f64;
        let avg_edge_num = self.executor.local_stats.avg_edge_num.get() as f64;

        if edge_num * 0.3 > avg_edge_num {
            mutation_score *= 3;
        
        } else if edge_num * 0.5 > avg_edge_num {
            mutation_score *= 2;
        
        } else if edge_num * 0.75 > avg_edge_num {
            mutation_score = (mutation_score as f64 * 1.5) as usize;
        
        } else if edge_num * 3.0 < avg_edge_num {
            mutation_score = (mutation_score as f64 * 0.25) as usize;
        
        } else if edge_num * 2.0 < avg_edge_num {
            mutation_score = (mutation_score as f64 * 0.5) as usize;
        
        } else if edge_num * 1.5 < avg_edge_num {
            mutation_score = (mutation_score as f64 * 0.75) as usize;
        
        }

        // Third, make sure score is not too large.
        mutation_score = min(mutation_score, config::HAVOC_MAX_MULT * 100);

        mutation_score
    }

}
