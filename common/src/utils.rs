use crate::config;
use rand::Rng;

pub fn next_p2(val: usize) -> usize {
    if val <= 1 {
        return 1;
    }
    let mut ret = 1;
    while val > ret {
        ret <<= 1;
    }
    ret
}

// Choose a mutation start point based on mutation history to optimize fuzzing efficiency.
// Return 0 - (length - 1)
pub fn choose_start_point(length: usize, position: usize, rng: &mut impl Rng) -> usize {
    let chunk_size = length / config::POSITION_NUM;

    if chunk_size == 0 {
        // Testcase is too short!
        rng.gen_range(0..length)
    } else {
        if position == config::POSITION_NUM - 1 {
            let start = chunk_size * position;
            let end = length;
            rng.gen_range(start..end)
        } else {
            let start = chunk_size * position;
            let end = chunk_size * (position + 1);
            assert!(end <= length);
            rng.gen_range(start..end)
        }
    }
}