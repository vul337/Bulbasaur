use bulbasaur_common::{config, utils};
use crate::{depot::SeedInfo, executor::StatusType, search::SearchHandler};
use std::cmp::{max, min};
use config::{TRIM_START_STEPS, TRIM_MIN_BYTES, TRIM_END_STEPS};


pub fn trim_case(handler: &mut SearchHandler) {
    
    if handler.executor.depot.is_seed_trimmed(handler.seed_info.seed_id) {
        return;
    }

    let mut tmp_buf = handler.buf.clone();
    let mut len_p2 = utils::next_p2(tmp_buf.len());
    let mut remove_len = max(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES);
    let status = handler.execute(&tmp_buf, SeedInfo::default());
    if status != StatusType::Normal {
        warn!("Execute input {:?} encounter abnormal status in trim_case: {:?}, skip it", 
            handler.seed_info.seed_id, status);
        return;
    }

    let orig_hash = handler.executor.branches.get_trace_map_hash();
    let mut need_write = false;

    while remove_len >= max(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES) {
        let mut remove_pos = remove_len;

        while remove_pos < tmp_buf.len() {

            let trim_avail = min(remove_len, tmp_buf.len() - remove_pos);
            let back = tmp_buf[remove_pos..remove_pos + trim_avail].to_vec();

            // // Debug.
            // let check_buf = tmp_buf.clone();
            tmp_buf.drain(remove_pos..remove_pos + trim_avail);
            handler.execute(&tmp_buf, SeedInfo::default());
            let now_hash = handler.executor.branches.get_trace_map_hash();
            if now_hash == orig_hash {
                len_p2 = utils::next_p2(tmp_buf.len());
                need_write = true;

            } else {
                // restore
                tmp_buf.splice(remove_pos..remove_pos, back);
                remove_pos += remove_len;
                // //  Debug
                // for idx in 0..tmp_buf.len() {
                //     assert!(tmp_buf[idx] == check_buf[idx])
                // }
            }
        }

        remove_len >>= 1;
    }

    if need_write {
        assert!(tmp_buf.len() < handler.buf.len());
        handler.executor.depot.rewrite_input(&tmp_buf, handler.seed_info.seed_id);
        // Move tmp_buf.
        handler.buf = tmp_buf;
    }
    handler.executor.depot.seed_trim_done(handler.seed_info.seed_id)
}