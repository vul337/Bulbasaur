/// Mutation function type for Agent-generated mutation functions.
/// 
/// Mutation functions take a mutable pointer to a Vec<u8> buffer
/// and the two operand values that reached the branch, then apply
/// mutations to help break through a specific branch.
/// 
/// Returns:
/// - `1` if the mutation was successfully applied (input was modified)
/// - `0` if no mutation was applied (input unchanged)
/// - `-1` if an error occurred (panic was caught internally)
/// 
/// IMPORTANT: The function MUST internally catch all panics using `catch_unwind`
/// and return -1 instead of letting panic cross the FFI boundary.
/// 
/// The function signature for exported functions should be:
/// ```rust,ignore
/// #[no_mangle]
/// pub extern "C" fn mutate_branch_42(
///     buf: *mut Vec<u8>,
///     op1_substr: *const Vec<u8>,
///     op2_substr: *const Vec<u8>
/// ) -> i32 {
///     // Wrap all logic in catch_unwind to prevent panic from crossing FFI boundary
///     std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
///         // Mutation logic here
///         // Return 1 if mutation successful, 0 if no mutation
///     })).unwrap_or(-1)  // Return -1 if panic occurred
/// }
/// ```
pub type MutateFunc = extern "C" fn(*mut Vec<u8>, *const Vec<u8>, *const Vec<u8>) -> i32;

#[derive(Debug, Clone)]
pub struct BranchMutateInfo {
    pub mutate_func: Option<MutateFunc>,
    pub is_covered: bool,
    pub reach_time: usize,
    pub retry_count: usize,
}

impl Default for BranchMutateInfo {
    fn default() -> Self {
        Self {
            mutate_func: None,
            is_covered: false,
            reach_time: 0,
            retry_count: 0,
        }
    }
}
