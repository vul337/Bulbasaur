/*
    Contains all mutators from AFLpp.
*/
use super::*;
use rand::Rng;

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub enum AFLMutator {
    BitFilp,
    Int8,
    Int16,
    Int16Be,
    Int32,
    Int32Be,
    Arith8Sub,
    Arith8Add,
    Arith16Sub,
    Arith16SubBe,
    Arith16Add,
    Arith16AddBe,
    Arith32Add,
    Arith32AddBe,
    Arith32Sub,
    Arith32SubBe,
    Rand8,
    CloneCopy,
    CloneFixed,
    OverWriteCopy,
    OverWriteFixed,
    ByteAdd,
    ByteSub,
    BitFilp8,
    Switch,
    Del,
    Shuffle,
    DelOne,
    InsertOne,
    AsciiNum,
    InsertAsciiNum,
    SpliceOverwrite,
    SpliceInsert,
    ExtraInsert,
    ExtraOverwrite,
    TraceCmpData,
    ConstStrcmpInsert,
    ConstStrcmpOverwrite,
    ConstCmpDataBe,
    ConstCmpData,
    // TraceCmpDataBe,
}

fn choose_block_len(rng: &mut impl Rng, limit: u32) -> u32 {

    let (mut min_value, mut max_value) = match rng.gen_range(0..3) {
        0 => (1, config::HAVOC_BLK_SMALL as u32),
        1 => (config::HAVOC_BLK_SMALL as u32, config::HAVOC_BLK_MEDIUM as u32),
        _ => {
            if rng.gen_range(0..10) > 0 {
                (config::HAVOC_BLK_MEDIUM as u32, config::HAVOC_BLK_LARGE as u32)
            } else {
                (config::HAVOC_BLK_LARGE as u32, config::HAVOC_BLK_XL as u32)
            }
        }
    };

    if min_value >= limit {
        min_value = 1;
    }
    max_value = max_value.min(limit);

    min_value + rng.gen_range(0..(max_value - min_value + 1))
}

pub fn mut_bitflip(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    let len = buf.len();
    if len == 0 {
        return;
    }

    let bit = rng.gen_range(0..8);
    let off = rng.gen_range(0..len) as usize;

    buf[off] ^= 1 << bit;
}

pub fn mut_interesting8(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.is_empty() {
        return;
    }

    let item_index = rng.gen_range(0..INTERESTING_8.len());
    let byte_index = rng.gen_range(0..buf.len());
    buf[byte_index] = INTERESTING_8[item_index] as u8;
}

pub fn mut_interesting16(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    let len = buf.len();
    if len < 2 {
        return;
    }

    let item = rng.gen_range(0..INTERESTING_16.len());
    let pos = rng.gen_range(0..len - 1);
    
    let bytes = INTERESTING_16[item].to_le_bytes(); // Little Endian
    buf[pos] = bytes[0];
    buf[pos + 1] = bytes[1];
}

pub fn mut_interesting16_be(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    let len = buf.len();
    if len < 2 {
        return;
    }

    let item = rng.gen_range(0..INTERESTING_16.len());
    let pos = rng.gen_range(0..len - 1);

    let bytes = INTERESTING_16[item].to_be_bytes(); // Big Endian
    buf[pos] = bytes[0];
    buf[pos + 1] = bytes[1];
}

pub fn mut_interesting32(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 4 {
        return;
    }

    let item_index = rng.gen_range(0..INTERESTING_32.len());
    let byte_index = rng.gen_range(0..(buf.len() - 3));

    buf[byte_index..byte_index + 4].copy_from_slice(&INTERESTING_32[item_index].to_le_bytes());
}

pub fn mut_interesting32_be(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 4 {
        return;
    }

    let item_index = rng.gen_range(0..INTERESTING_32.len());
    let byte_index = rng.gen_range(0..(buf.len() - 3));

    buf[byte_index..byte_index + 4].copy_from_slice(&INTERESTING_32[item_index].to_be_bytes());
}

pub fn mut_arith8_sub(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.is_empty() {
        return;
    }
    let item: u8 = 1 + rng.gen_range(0..config::ARITH_MAX as u8);
    let index = rng.gen_range(0..buf.len());
    buf[index] = buf[index].wrapping_sub(item);
}

pub fn mut_arith8_add(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.is_empty() {
        return;
    }
    let item: u8 = 1 + rng.gen_range(0..config::ARITH_MAX as u8);
    let index = rng.gen_range(0..buf.len());
    buf[index] = buf[index].wrapping_add(item);
}

pub fn mut_arith16_sub(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 2 {
        return;
    }
    let pos = rng.gen_range(0..buf.len() - 1);
    let item: u16 = 1 + rng.gen_range(0..config::ARITH_MAX as u16);
    let mut num = u16::from_le_bytes([buf[pos], buf[pos + 1]]);
    num = num.wrapping_sub(item);
    buf[pos..pos + 2].copy_from_slice(&num.to_le_bytes());
}

pub fn mut_arith16_sub_be(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 2 {
        return;
    }
    let pos = rng.gen_range(0..buf.len() - 1);
    let num = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let item: u16 = 1 + rng.gen_range(0..config::ARITH_MAX as u16);
    let new_val = num.wrapping_sub(item);
    buf[pos..pos + 2].copy_from_slice(&new_val.to_be_bytes());
}

pub fn mut_arith16_add(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 2 {
        return;
    }
    let pos = rng.gen_range(0..buf.len() - 1);
    let num = u16::from_le_bytes([buf[pos], buf[pos + 1]]);
    
    let item: u16 = 1 + rng.gen_range(0..config::ARITH_MAX as u16);
    let new_val = num.wrapping_add(item);
    buf[pos..pos + 2].copy_from_slice(&new_val.to_le_bytes());
}

pub fn mut_arith16_add_be(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 2 {
        return;
    }
    let pos = rng.gen_range(0..buf.len() - 1);
    let num = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    
    let item: u16 = 1 + rng.gen_range(0..config::ARITH_MAX as u16);
    let new_val = num.wrapping_add(item);
    buf[pos..pos + 2].copy_from_slice(&new_val.to_be_bytes());
}

pub fn mut_arith32_sub(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 4 {
        return;
    }
    let pos = rng.gen_range(0..buf.len() - 3);

    let num = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
    let item: u32 = 1 + rng.gen_range(0..config::ARITH_MAX as u32);
    let new_val = num.wrapping_sub(item);

    buf[pos..pos + 4].copy_from_slice(&new_val.to_le_bytes());
}

pub fn mut_arith32_sub_be(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 4 {
        return;
    }
    let pos = rng.gen_range(0..buf.len() - 3);

    let num = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
    let item: u32 = 1 + rng.gen_range(0..config::ARITH_MAX as u32);
    let new_val = num.wrapping_sub(item);

    buf[pos..pos + 4].copy_from_slice(&new_val.to_be_bytes());
}

pub fn mut_arith32_add(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 4 {
        return;
    }
    let pos = rng.gen_range(0..buf.len() - 3);

    let num = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
    let item: u32 = 1 + rng.gen_range(0..config::ARITH_MAX as u32);
    let new_val = num.wrapping_add(item);

    buf[pos..pos + 4].copy_from_slice(&new_val.to_le_bytes());
}

pub fn mut_arith32_add_be(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 4 {
        return;
    }
    let pos = rng.gen_range(0..buf.len() - 3);

    let num = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
    let item: u32 = 1 + rng.gen_range(0..config::ARITH_MAX as u32);
    let new_val = num.wrapping_add(item);

    buf[pos..pos + 4].copy_from_slice(&new_val.to_be_bytes());
}

pub fn mut_rand8(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.is_empty() {
        return;
    }
    let pos = rng.gen_range(0..buf.len());
    let item: u8 = 1 + rng.gen_range(0..255);
    buf[pos] ^= item;
}

pub fn mut_clone_copy(buf: &mut Vec<u8>, rng: &mut impl Rng, tmp_buf: &mut Vec<u8>) {

    if (buf.len() + config::HAVOC_BLK_XL as usize) >= config::MAX_INPUT_LEN {
        return;
    }

    let clone_len: u32 = choose_block_len(rng, buf.len() as u32);
    let clone_from: u32 = rng.gen_range(0..(buf.len() as u32 - clone_len + 1));
    let clone_to: u32 = rng.gen_range(0..buf.len() as u32);
    let old_len: u32 = buf.len() as u32;
    let new_len = old_len + clone_len;

    tmp_buf.resize(new_len as usize, 0);

    unsafe {
        let dst_ptr = tmp_buf.as_mut_ptr();
        let src_ptr = buf.as_ptr();
        ptr::copy_nonoverlapping(src_ptr, dst_ptr, clone_to as usize);
        ptr::copy_nonoverlapping(src_ptr.offset(clone_from as isize), dst_ptr.offset(clone_to as isize), clone_len as usize);
        ptr::copy_nonoverlapping(src_ptr.offset(clone_to as isize), dst_ptr.offset(clone_to as isize + clone_len as isize), (old_len - clone_to) as usize);
    }

    // most efficient
    std::mem::swap(buf, tmp_buf);
}

pub fn mut_clone_fixed(buf: &mut Vec<u8>, rng: &mut impl Rng, tmp_buf: &mut Vec<u8>) {

    if (buf.len() + config::HAVOC_BLK_XL as usize) >= (config::MAX_INPUT_LEN as usize) {
        return;
    }

    let clone_len: u32 = choose_block_len(rng, config::HAVOC_BLK_XL);
    let clone_to: u32 = rng.gen_range(0..buf.len() as u32);
    let strat = rng.gen_bool(0.5);
    let clone_from = if clone_to > 0 { clone_to - 1 } else { 0 };
    let item = if strat { rng.gen_range(0..=255) as u8 } else { buf[clone_from as usize] };
    let new_len = buf.len() as u32 + clone_len;

    tmp_buf.resize(new_len as usize, 0);

    unsafe {
        let dst_ptr = tmp_buf.as_mut_ptr();
        let src_ptr = buf.as_ptr();
        ptr::copy_nonoverlapping(src_ptr, dst_ptr, clone_to as usize);
        ptr::write_bytes(dst_ptr.offset(clone_to as isize), item, clone_len as usize);
        ptr::copy_nonoverlapping(src_ptr.offset(clone_to as isize), dst_ptr.offset(clone_to as isize + clone_len as isize), buf.len() - clone_to as usize);
    }

    std::mem::swap(buf, tmp_buf);
}

pub fn mut_overwrite_copy(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 2 {
        return;
    }

    let copy_len = choose_block_len(rng, buf.len() as u32 - 1);

    let (mut copy_from, mut copy_to);
    loop {
        copy_from = rng.gen_range(0..=buf.len() as u32 - copy_len);
        copy_to = rng.gen_range(0..=buf.len() as u32 - copy_len);
        if copy_from != copy_to {
            break;
        }
    }

    buf.copy_within(copy_from as usize..(copy_from + copy_len) as usize, copy_to as usize);
}

pub fn mut_overwrite_fixed(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 2 {
        return;
    }

    let copy_len = choose_block_len(rng, buf.len() as u32 - 1);
    let copy_to = rng.gen_range(0..=buf.len() as u32 - copy_len);
    let strat = rng.gen_bool(0.5);
    let copy_from = if copy_to > 0 { copy_to - 1 } else { 0 };
    let item = if strat { rng.gen_range(0..=255) as u8 } else { buf[copy_from as usize] };

    unsafe {
        std::ptr::write_bytes(buf.as_mut_ptr().offset(copy_to as isize), item, copy_len as usize);
    }
}

pub fn mut_byte_add(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.is_empty() {
        return;
    }
    let idx = rng.gen_range(0..buf.len());
    buf[idx] = buf[idx].wrapping_add(1);
}

pub fn mut_byte_sub(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.is_empty() {
        return;
    }
    let idx = rng.gen_range(0..buf.len());
    buf[idx] = buf[idx].wrapping_sub(1);
}

pub fn mut_bitflip8(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.is_empty() {
        return;
    }
    let idx = rng.gen_range(0..buf.len());
    buf[idx] ^= 0xff;
}

pub fn mut_switch(buf: &mut Vec<u8>, rng: &mut impl Rng, tmp_buf: &mut Vec<u8>) {
    if buf.len() < 4 {
        return;
    }

    let switch_from = rng.gen_range(0..buf.len());
    let mut switch_to;
    
    loop {
        switch_to = rng.gen_range(0..buf.len());
        if switch_to != switch_from {
            break;
        }
    }

    let (switch_len, to_end) = if switch_from < switch_to {
        (switch_to - switch_from, buf.len() - switch_to)
    } else {
        (switch_from - switch_to, buf.len() - switch_from)
    };

    let switch_len = choose_block_len(rng, switch_len.min(to_end) as u32);


    tmp_buf.resize(switch_len as usize, 0);

    unsafe {
        /* Backup */
        ptr::copy_nonoverlapping(buf.as_ptr().offset(switch_from as isize), tmp_buf.as_mut_ptr(), switch_len as usize);
        /* Switch 1 */
        ptr::copy_nonoverlapping(buf.as_ptr().offset(switch_to as isize), buf.as_mut_ptr().offset(switch_from as isize), switch_len as usize);
    }
    /* Switch 2 */
    buf[switch_to..switch_to + switch_len as usize].copy_from_slice(&tmp_buf[..switch_len as usize]);
}

pub fn mut_del(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 2 {
        return;
    }

    let del_len = choose_block_len(rng, buf.len() as u32 - 1);
    let del_from = rng.gen_range(0..=buf.len() - del_len as usize);

    buf.drain(del_from..del_from + del_len as usize);
}

pub fn mut_shuffle(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 4 {
        return;
    }

    let len = choose_block_len(rng, buf.len() as u32 - 1);
    let off = rng.gen_range(0..=buf.len() - len as usize);

    let slice = &mut buf[off..off + len as usize];
    for i in (1..slice.len()).rev() {
        let j = rng.gen_range(0..i);
        slice.swap(i, j);
    }
}

pub fn mut_del_one(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 2 {
        return;
    }

    let del_from = rng.gen_range(0..buf.len());
    buf.remove(del_from);
}

pub fn mut_insert_one(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    if buf.len() < 2 {
        return;
    }

    let clone_to = rng.gen_range(0..=buf.len());
    let strat = rng.gen_bool(0.5);
    let clone_from = if clone_to > 0 { clone_to - 1 } else { 0 };
    let item = if strat { rng.gen_range(0..=255) } else { buf[clone_from] };

    buf.insert(clone_to, item);
}


pub fn mut_ascii_num(buf: &mut Vec<u8>, rng: &mut impl Rng, tmp_buf: &mut Vec<u8>) {
    if buf.len() < 4 {
        return;
    }

    let mut off = rng.gen_range(0..buf.len());
    let mut off2 = off;
    let mut cnt = 0;

    while off2 + cnt < buf.len() && !buf[off2 + cnt].is_ascii_digit() {
        cnt += 1;
    }

    // None found, wrap
    if off2 + cnt == buf.len() {
        off2 = 0;
        cnt = 0;

        while cnt < off && !buf[off2 + cnt].is_ascii_digit() {
            cnt += 1;
        }

        if cnt == off {
            if buf.len() < 8 {
                return;
            }
        }
    }

    off = off2 + cnt;
    off2 = off + 1;

    while off2 < buf.len() && buf[off2].is_ascii_digit() {
        off2 += 1;
    }

    // parse ASCII
    let num_str = std::str::from_utf8(&buf[off..off2]).unwrap_or("0");
    let mut val = num_str.parse::<i64>().unwrap_or(0);

    if off > 0 && buf[off - 1] == b'-' {
        val = -val;
    }

    match rng.gen_range(0..8) {
        0 => val = val.wrapping_add(1),
        1 => val = val.wrapping_sub(1),
        2 => val = val.wrapping_mul(2),
        3 => val /= 2,
        4 => {
            if val != 0 && (val as u64) < 0x19999999 {
                val = (rng.gen::<u64>() % (val as u64 * 10)) as i64;
            } else {
                val = rng.gen_range(0..256);
            }
        }
        5 => val = val.wrapping_add(rng.gen_range(0..256)),
        6 => val = val.wrapping_sub(rng.gen_range(0..256)),
        7 => val = !val,
        _ => {}
    }

    let new_num_str = val.to_string();
    let old_len = off2 - off;
    let new_len = new_num_str.len();

    if old_len == new_len {
        buf[off..off + new_len].copy_from_slice(new_num_str.as_bytes());
    } else {
        
        tmp_buf.resize(buf.len() + new_len - old_len, 0);

        unsafe {
            let dst_ptr = tmp_buf.as_mut_ptr();
            let src_ptr = buf.as_ptr();
            ptr::copy_nonoverlapping(src_ptr, dst_ptr, off);
            ptr::copy_nonoverlapping(new_num_str.as_ptr(), dst_ptr.offset(off as isize), new_len);
            ptr::copy_nonoverlapping(src_ptr.offset(off2 as isize), dst_ptr.offset((off as usize + new_len) as isize), buf.len() - off2);
        }

        std::mem::swap(buf, tmp_buf);
    }
}

pub fn mut_insert_ascii_num(buf: &mut Vec<u8>, rng: &mut impl Rng) {
    let len = rng.gen_range(1..=8);
    if buf.len() < len {
        return;
    }

    let pos = rng.gen_range(0..=buf.len() - len);
    let val: u64 = rng.gen::<u64>();
    let num_str = val.to_string();
    
    let num_bytes = num_str.as_bytes();
    let copy_len = len.min(num_bytes.len());

    buf[pos..pos + copy_len].copy_from_slice(&num_bytes[..copy_len]);
}

pub fn mut_splice_overwrite(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng) {
    let splice_buf = handler.executor.random_splice_input_buf(handler.seed_info.seed_id);
    if splice_buf.len() < 4 {
        return;
    }
    let mut copy_len = choose_block_len(rng, splice_buf.len() as u32 - 1);
    if copy_len > buf.len() as u32 {
        copy_len = buf.len() as u32;
    }

    let copy_from = rng.gen_range(0..splice_buf.len() + 1 - copy_len as usize);
    let copy_to = rng.gen_range(0..buf.len() + 1 - copy_len as usize);

    unsafe {
        let dst_ptr = buf.as_mut_ptr();
        let src_ptr = splice_buf.as_ptr();
        ptr::copy_nonoverlapping(src_ptr.offset(copy_from as isize), dst_ptr.offset(copy_to as isize), copy_len as usize);
    }
}

pub fn mut_splice_insert(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng, tmp_buf: &mut Vec<u8>) {
    if (buf.len() + config::HAVOC_BLK_XL as usize) >= config::MAX_INPUT_LEN {
        return;
    }
    let splice_buf = handler.executor.random_splice_input_buf(handler.seed_info.seed_id);
    if splice_buf.len() < 4 {
        return;
    }
    let clone_len = choose_block_len(rng, splice_buf.len() as u32);

    let clone_from = rng.gen_range(0..splice_buf.len() - clone_len as usize + 1);
    let clone_to = rng.gen_range(0..buf.len() + 1);

    tmp_buf.resize(buf.len() + clone_len as usize + 1, 0);

    unsafe {
        let dst_ptr = tmp_buf.as_mut_ptr();
        ptr::copy_nonoverlapping(buf.as_ptr(), dst_ptr, clone_to);
        ptr::copy_nonoverlapping(splice_buf.as_ptr().offset(clone_from as isize), dst_ptr.offset(clone_to as isize), clone_len as usize);
        ptr::copy_nonoverlapping(buf.as_ptr().offset(clone_to as isize), 
                                dst_ptr.offset(clone_to as isize + clone_len as isize), 
                                buf.len() - clone_to);
    }

    std::mem::swap(buf, tmp_buf);
}

// pub fn mut_trace_extra_insert(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng) {
//     if handler.strcmp_data_vec.len() == 0 {
//         return
//     }
//     let trace_extra = &handler.strcmp_data_vec[rng.gen_range(0..handler.strcmp_data_vec.len())];

//     if (buf.len() + trace_extra.len) >= config::MAX_INPUT_LEN {
//         return;
//     }

//     let clone_to = rng.gen_range(0..=buf.len());
//     buf.splice(clone_to..clone_to, trace_extra.data.iter().cloned());
// }

// pub fn mut_trace_extra_overwrite(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng) {
//     if handler.strcmp_data_vec.len() == 0 {
//         return
//     }
//     let trace_extra = &handler.strcmp_data_vec[rng.gen_range(0..handler.strcmp_data_vec.len())];

//     if trace_extra.len > buf.len() {
//         return;
//     }

//     let clone_to = rng.gen_range(0..=(buf.len() - trace_extra.len));
//     buf.splice(clone_to..clone_to + trace_extra.len, trace_extra.data.iter().cloned());
// }

// pub fn mut_trace_cmp_data_be(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng) {
//     if handler.cmp_data_in_direct_copy.len() == 0 {
//         return;
//     }

//     let trace_cmp_data = &handler.cmp_data_in_direct_copy[rng.gen_range(0..handler.cmp_data_in_direct_copy.len())];
    
//     let op1_substr: Vec<u8> = trace_cmp_data.0.iter().rev().cloned().collect();
//     let op2_substr: Vec<u8> = trace_cmp_data.1.iter().rev().cloned().collect();

//     let max_len = op1_substr.len().max(op2_substr.len());
//     if buf.len() < max_len {
//         return;
//     }

//     let mut pos = rng.gen_range(0..=buf.len() - max_len);
    
//     while pos + max_len <= buf.len() {
//         if &buf[pos..pos + op1_substr.len()] == op1_substr.as_slice() {
//             buf.splice(pos..pos + op1_substr.len(), op2_substr.clone());
//             break;
//         } else if &buf[pos..pos + op2_substr.len()] == op2_substr.as_slice() {
//             buf.splice(pos..pos + op2_substr.len(), op1_substr.clone());
//             break;
//         }
//         pos += 1;
//     }
// }

pub fn mut_trace_cmp_data(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng) {
    if handler.cmp_data_in_direct_copy.len() == 0 {
        return;
    }

    let trace_cmp_data = &handler.cmp_data_in_direct_copy[rng.gen_range(0..handler.cmp_data_in_direct_copy.len())];
    
    let op1_substr: Vec<u8> = trace_cmp_data.0.iter().rev().cloned().collect();
    let op2_substr: Vec<u8> = trace_cmp_data.1.iter().rev().cloned().collect();
    let rev_op1: Vec<u8> = op1_substr.iter().rev().cloned().collect();
    let rev_op2: Vec<u8> = op2_substr.iter().rev().cloned().collect();

    let max_len = op1_substr.len().max(op2_substr.len());
    if buf.len() < max_len {
        return;
    }

    let mut pos = rng.gen_range(0..=buf.len() - max_len);
    
    while pos + max_len <= buf.len() {
        if &buf[pos..pos + op1_substr.len()] == op1_substr.as_slice() {
            buf.splice(pos..pos + op1_substr.len(), op2_substr.clone());
            break;
        } else if &buf[pos..pos + op2_substr.len()] == op2_substr.as_slice() {
            buf.splice(pos..pos + op2_substr.len(), op1_substr.clone());
            break;
        } else if &buf[pos..pos + op1_substr.len()] == rev_op1.as_slice() {
            buf.splice(pos..pos + op1_substr.len(), rev_op2.clone());
            break;
        } else if &buf[pos..pos + op2_substr.len()] == rev_op2.as_slice() {
            buf.splice(pos..pos + op2_substr.len(), rev_op1.clone());
            break;
        }
        pos += 1;
    }
}

pub fn mut_extra_insert(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng) {
    let extra_data = handler.get_extra_data();
    if extra_data.len() == 0 {
        return
    }
    let extra = &extra_data[rng.gen_range(0..extra_data.len())];

    if (buf.len() + extra.len) >= config::MAX_INPUT_LEN {
        return;
    }

    let clone_to = rng.gen_range(0..=buf.len());
    buf.splice(clone_to..clone_to, extra.data.iter().cloned());
}

pub fn mut_extra_overwrite(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng) {
    let extra_data = handler.get_extra_data();
    if extra_data.len() == 0 {
        return
    }
    let extra = &extra_data[rng.gen_range(0..extra_data.len())];

    if extra.len > buf.len() {
        return;
    }

    let clone_to = rng.gen_range(0..=(buf.len() - extra.len));
    buf.splice(clone_to..clone_to + extra.len, extra.data.iter().cloned());
}

pub fn mut_const_strcmp_insert(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng) {
    if handler.const_strcmp_data_vec.len() == 0 {
        return
    }
    let trace_extra = &handler.const_strcmp_data_vec[rng.gen_range(0..handler.const_strcmp_data_vec.len())];

    if (buf.len() + trace_extra.len) >= config::MAX_INPUT_LEN {
        return;
    }

    let clone_to = rng.gen_range(0..=buf.len());
    buf.splice(clone_to..clone_to, trace_extra.data.iter().cloned());
}

pub fn mut_const_strcmp_overwrite(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng) {
    if handler.const_strcmp_data_vec.len() == 0 {
        return
    }
    let trace_extra = &handler.const_strcmp_data_vec[rng.gen_range(0..handler.const_strcmp_data_vec.len())];

    if trace_extra.len > buf.len() {
        return;
    }

    let clone_to = rng.gen_range(0..=(buf.len() - trace_extra.len));
    buf.splice(clone_to..clone_to + trace_extra.len, trace_extra.data.iter().cloned());
}

pub fn mut_const_cmp_data_be(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng) {
    if handler.const_cmp_data_vec.len() == 0 {
        return;
    }
    let trace_cmp_data = handler.const_cmp_data_vec[rng.gen_range(0..handler.const_cmp_data_vec.len())];
    
    let value_len = trace_cmp_data.1;
    let bytes = &trace_cmp_data.0.to_be_bytes()[(8 - value_len)..];

    if buf.len() < value_len {
        return;
    }

    let byte_index = rng.gen_range(0..=(buf.len() - value_len));
    buf[byte_index..byte_index + value_len].copy_from_slice(&bytes);
}

pub fn mut_const_cmp_data(buf: &mut Vec<u8>, handler: &mut SearchHandler, rng: &mut impl Rng) {
    if handler.const_cmp_data_vec.len() == 0 {
        return;
    }
    let trace_cmp_data = handler.const_cmp_data_vec[rng.gen_range(0..handler.const_cmp_data_vec.len())];
    
    let value_len = trace_cmp_data.1;
    let bytes = &trace_cmp_data.0.to_le_bytes()[..value_len];

    if buf.len() < value_len {
        return;
    }

    let byte_index = rng.gen_range(0..=(buf.len() - value_len));
    buf[byte_index..byte_index + value_len].copy_from_slice(&bytes);
}
