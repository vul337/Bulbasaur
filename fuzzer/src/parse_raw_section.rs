// Parse raw section data acquired from pipes.

use std::collections::HashMap;
use std::convert::TryInto;
use crate::branches::BranchType;

// The `__edge_to_pred_br` section contains pairs of edge IDs and their predecessor branch IDs.
pub fn parse_edge_to_pred_branch(edge_to_pred_branch_raw_data: Vec<u8>) -> (HashMap<usize, usize>, HashMap<usize, usize>) {
    // Each record is two u64 values (edge_id, branch_id) = 16 bytes
    assert!(edge_to_pred_branch_raw_data.len() % 16 == 0,
            "__edge_to_pred_br section size {} is not a multiple of 16", edge_to_pred_branch_raw_data.len());
    let mut edge_to_pred_branch_dict = HashMap::<usize, usize>::new();
    let mut branch_boundary = HashMap::<usize, usize>::new();

    let mut edge_to_branch_idx = 0;
    
    while edge_to_branch_idx < edge_to_pred_branch_raw_data.len() {
        let edge_id = u64::from_ne_bytes(
                            edge_to_pred_branch_raw_data[edge_to_branch_idx..edge_to_branch_idx + 8]
                            .try_into()
                            .expect("slice with incorrect length"));

        let branch_id = u64::from_ne_bytes(
                            edge_to_pred_branch_raw_data[edge_to_branch_idx + 8..edge_to_branch_idx + 16]
                            .try_into()
                            .expect("slice with incorrect length"));

        *branch_boundary.entry(branch_id as usize).or_insert(0) += 1;

        let old = edge_to_pred_branch_dict.insert(edge_id as usize, branch_id as usize);
        assert!(old.is_none(), "edge_id exists");

        edge_to_branch_idx += 16;
    }

    (edge_to_pred_branch_dict, branch_boundary)
}


// The `__branch_type` section contains pairs of branch IDs and their types.
pub fn parse_branch_type(branch_type_raw_data: Vec<u8>) -> HashMap<usize, BranchType> {
    // Each record is two u64 values (branch_id, type_tag) = 16 bytes
    assert!(branch_type_raw_data.len() % 16 == 0,
            "__branch_type section size {} is not a multiple of 16", branch_type_raw_data.len());
    let mut branch_type_dict = HashMap::<usize, BranchType>::new();

    let mut branch_type_idx = 0;
    
    while branch_type_idx < branch_type_raw_data.len() {
        let branch_id = u64::from_ne_bytes(
                            branch_type_raw_data[branch_type_idx..branch_type_idx + 8]
                            .try_into()
                            .expect("slice with incorrect length"));

        let branch_type = u64::from_ne_bytes(
                            branch_type_raw_data[branch_type_idx + 8..branch_type_idx + 16]
                            .try_into()
                            .expect("slice with incorrect length"));
        let branch_type = match branch_type {
                1 => BranchType::Cmp,
                2 => BranchType::ConstCmp,
                3 => BranchType::Switch,
                4 => BranchType::FCmp,
                5 => BranchType::Strcmp,
                6 => BranchType::ConstStrcmp,
                7 => BranchType::StrcmpNonTerm,
                8 => BranchType::ConstStrcmpNonTerm,
                9 => BranchType::RtnFunction,
                _ => panic!("unknown branch type value: {}", branch_type)
            };

        let old = branch_type_dict.insert(branch_id as usize, branch_type);
            assert!(old.is_none(), "branch_index exists");

        branch_type_idx += 16;
    }

    branch_type_dict
}