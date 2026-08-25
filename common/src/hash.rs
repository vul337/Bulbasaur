use ahash::AHasher;
use std::hash::{Hash, Hasher};

pub fn hash_slice(data: &[u8]) -> u64 {
    let mut hasher = AHasher::default();
    data.hash(&mut hasher);
    hasher.finish()
}