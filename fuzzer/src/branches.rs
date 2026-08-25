use crate::{depot::SeedInfo, executor::StatusType};
use bulbasaur_common::mutate_func::BranchMutateInfo;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::depot::Depot;
use crate::stats::LocalStats;
use bulbasaur_common::config::BRANCH_CONTEXT_CNT;
use bulbasaur_common::{config::TMP_MAP_SIZE, shm::SHM};
use bulbasaur_common::trace_data;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};
use rand::rngs::ThreadRng;
use rand::Rng;
use num::integer::gcd;

// BranchType mirrors the values emitted by the instrumentation passes (bulbasaur-cov-*.so).
// The instrumentation writes one entry per comparison site; this enum lets the fuzzer
// know how to interpret the trace operands.
#[derive(PartialEq, Eq, Debug, Display, Clone, Copy)]
pub enum BranchType {
    Cmp,               // Integer comparison (ICmp)
    ConstCmp,          // ICmp with one constant operand
    Switch,            // Switch statement case
    FCmp,              // Floating-point comparison
    Strcmp,            // Dynamic strcmp/strncmp/memcmp
    ConstStrcmp,       // strcmp against a constant string literal
    StrcmpNonTerm,     // Non-null-terminated string comparison
    ConstStrcmpNonTerm,
    RtnFunction,       // Return-value comparison (unused at runtime)
}

// Edge hit-count bucketing: maps raw count 0-255 to one of 8 buckets.
// Bucket boundaries: [1],[2],[3],[4-7],[8-15],[16-31],[32-127],[128-255]
static EDGE_LOOKUP: [u8; 256] = [
    0, 1, 2, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
];

// Branch hit-count bucketing: maps raw count 0-63 to one of 8 buckets.
// Bucket boundaries: [1],[2],[3],[4-6],[7-12],[13-20],[21-35],[36-63]
pub static BRANCH_LOOKUP: [u8; 64] = [
    0,
    1,
    2,
    3,
    4, 4, 4,
    5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
];

// Dimensions for the three SHM bitmaps the fuzzer maintains.
#[derive(Debug, Clone)]
pub struct MapSizeData {
    pub real_map_size: usize,
    pub used_map_size: usize,
    pub real_branch_map_size: usize,
    pub used_branch_map_size: usize,
}

impl MapSizeData {
    pub fn new(
        real_map_size: usize,
        used_map_size: usize,
        real_branch_map_size: usize,
        used_branch_map_size: usize,
    ) -> Self {
        Self { real_map_size, used_map_size, real_branch_map_size, used_branch_map_size }
    }
}

/// Shared (Arc) state owned by all fuzzing threads.
///
/// The bitmap arrays are split into `thread_num` chunks, each protected by its
/// own `RwLock`, to let threads update disjoint chunks in parallel.  Each
/// thread iterates over chunks in a random coprime-step order (see
/// `Branches::random_chunk_order`) to avoid systematic lock contention.
pub struct GlobalBranches {
    // Per-chunk virgin bitmaps (0xFF = edge never seen).
    // Cleared on first hit; a cell goes to zero once all hit-count buckets have been observed.
    virgin_branches: Vec<RwLock<Box<[u8]>>>,
    tmouts_branches: Vec<RwLock<Box<[u8]>>>,
    crashes_branches: Vec<RwLock<Box<[u8]>>>,
    // Separate virgin map for the Full-pass target (may have different map dimensions).
    full_virgin_branches: Vec<RwLock<Box<[u8]>>>,

    // edge_favor_map[chunk][local_edge][ctx] = seed info with the best score for this (edge, context).
    edge_favor_map: Vec<RwLock<Box<[[SeedInfo; BRANCH_CONTEXT_CNT]]>>>,

    // Bit-per-branch coverage map: bit set once a branch is fully covered.
    global_branch_cov_map: RwLock<Box<[u8]>>,

    // branch_favor_map[chunk][local_branch][ctx] = seed info with the highest match value.
    branch_favor_map: Vec<RwLock<Box<[[SeedInfo; BRANCH_CONTEXT_CNT]]>>>,

    // Custom mutation function pointers loaded from the target's ELF sections.
    pub branch_mutate_funcs: Vec<RwLock<Box<[BranchMutateInfo]>>>,

    pub fast_map_size_data: MapSizeData,
    pub full_map_size_data: MapSizeData,
    pub trace_map_size_data: MapSizeData,

    // Global coverage counters (updated atomically).
    cov_edges: AtomicUsize,
    cov_branches: AtomicUsize,
    reached_branches: AtomicUsize,

    pub thread_num: usize,

    // Chunk boundary tables (parallel arrays, one entry per chunk).
    // [start_pos[i], end_pos[i]) is the global index range for chunk i.
    start_pos: Vec<usize>,
    end_pos: Vec<usize>,
    full_start_pos: Vec<usize>,
    full_end_pos: Vec<usize>,
    pub branch_start_pos: Vec<usize>,
    pub branch_end_pos: Vec<usize>,

    edge_to_pred_branch_dict: HashMap<usize, usize>,
    branch_type_dict: HashMap<usize, BranchType>,
    trace_branch_type_dict: HashMap<usize, BranchType>,

    // branch_boundary[branch_id] = set of edges that must be hit before this branch is "covered".
    // Becomes empty once all required edges have been observed.
    pub branch_boundary: RwLock<Vec<Vec<usize>>>,
}

impl GlobalBranches {
    pub fn new(
        n: usize,
        fast_map_size_data: MapSizeData,
        full_map_size_data: MapSizeData,
        trace_map_size_data: MapSizeData,
        edge_to_pred_branch_dict: HashMap<usize, usize>,
        branch_type_dict: HashMap<usize, BranchType>,
        trace_branch_type_dict: HashMap<usize, BranchType>,
    ) -> Self {
        assert!(n > 0, "n must be greater than 0");

        let (virgin_branches, start_pos, end_pos) =
            Self::create_chunks::<u8>(255, fast_map_size_data.used_map_size, n);
        let (tmouts_branches, _, _) =
            Self::create_chunks::<u8>(255, fast_map_size_data.used_map_size, n);
        let (crashes_branches, _, _) =
            Self::create_chunks::<u8>(255, fast_map_size_data.used_map_size, n);
        let (edge_favor_map, _, _) =
            Self::create_chunks::<[SeedInfo; 8]>([SeedInfo::default(); 8], fast_map_size_data.used_map_size, n);

        let (full_virgin_branches, full_start_pos, full_end_pos) =
            Self::create_chunks::<u8>(255, full_map_size_data.used_map_size, n);

        let (branch_favor_map, branch_start_pos, branch_end_pos) =
            Self::create_chunks::<[SeedInfo; BRANCH_CONTEXT_CNT]>(
                [SeedInfo::default(); BRANCH_CONTEXT_CNT],
                fast_map_size_data.used_branch_map_size,
                n,
            );
        let (branch_mutate_funcs, _, _) =
            Self::create_chunks::<BranchMutateInfo>(BranchMutateInfo::default(), fast_map_size_data.used_branch_map_size, n);

        let branch_boundary = RwLock::new(vec![Vec::new(); fast_map_size_data.used_branch_map_size]);
        {
            let mut bb = branch_boundary.write().unwrap();

            for (&edge, &branch) in &edge_to_pred_branch_dict {
                assert!(bb[branch].len() <= 1, "branch_boundary[{}] exceeded 1", branch);
                bb[branch].push(edge);
            }

            for (&branch, branch_type) in &branch_type_dict {
                if *branch_type == BranchType::StrcmpNonTerm
                    || *branch_type == BranchType::ConstStrcmpNonTerm
                {
                    // Non-terminated strcmp branches are counted as covered once they return max match value.
                    assert!(bb[branch].is_empty(), "branch_boundary[{}] is not empty", branch);
                    bb[branch].push(0);
                }
                assert!(*branch_type != BranchType::RtnFunction);
            }

            for (_, branch_type) in &trace_branch_type_dict {
                assert!(*branch_type != BranchType::RtnFunction);
            }

            for idx in 1..full_map_size_data.real_branch_map_size {
                assert!(bb[idx].len() != 0, "branch_boundary[{}] is 0.", idx);
            }
        }

        Self {
            virgin_branches,
            tmouts_branches,
            crashes_branches,
            full_virgin_branches,
            edge_favor_map,
            global_branch_cov_map: RwLock::new(
                vec![0u8; fast_map_size_data.used_branch_map_size / 8].into_boxed_slice(),
            ),
            branch_favor_map,
            branch_mutate_funcs,
            fast_map_size_data,
            full_map_size_data,
            trace_map_size_data,
            cov_edges: AtomicUsize::new(0),
            cov_branches: AtomicUsize::new(0),
            reached_branches: AtomicUsize::new(0),
            thread_num: n,
            start_pos,
            end_pos,
            full_start_pos,
            full_end_pos,
            branch_start_pos,
            branch_end_pos,
            edge_to_pred_branch_dict,
            branch_type_dict,
            trace_branch_type_dict,
            branch_boundary,
        }
    }

    pub fn get_edge_stats(&self) -> (usize, usize, f32) {
        let cov_edges = self.cov_edges.load(Ordering::Relaxed);
        let percent = (cov_edges * 10000 / self.fast_map_size_data.real_map_size) as f32 / 100.0;
        (cov_edges, self.fast_map_size_data.real_map_size, percent)
    }

    pub fn get_branch_stats(&self) -> (usize, usize, f32) {
        let cov_branches = self.cov_branches.load(Ordering::Relaxed);
        let percent =
            (cov_branches * 10000 / self.fast_map_size_data.real_branch_map_size) as f32 / 100.0;
        (cov_branches, self.fast_map_size_data.real_branch_map_size, percent)
    }

    pub fn get_reached_branches(&self) -> usize {
        self.reached_branches.load(Ordering::Relaxed)
    }

    /// Returns the chunk index that owns `branch_id` (binary search on sorted start_pos).
    pub fn branch_chunk_of(&self, branch_id: usize) -> usize {
        self.branch_start_pos
            .partition_point(|&s| s <= branch_id)
            .saturating_sub(1)
    }

    fn create_chunks<T: Clone>(
        fill_value: T,
        total_size: usize,
        chunk_num: usize,
    ) -> (Vec<RwLock<Box<[T]>>>, Vec<usize>, Vec<usize>) {
        let chunk_size = total_size / chunk_num;
        let extra = total_size % chunk_num;

        let mut current_pos: usize = 0;
        let mut start_pos = Vec::with_capacity(chunk_num);
        let mut end_pos = Vec::with_capacity(chunk_num);
        let chunks: Vec<RwLock<Box<[T]>>> = (0..chunk_num)
            .map(|i| {
                let size = if i < extra { chunk_size + 1 } else { chunk_size };
                start_pos.push(current_pos);
                current_pos += size;
                end_pos.push(current_pos - 1);
                RwLock::new(vec![fill_value.clone(); size].into_boxed_slice())
            })
            .collect();

        (chunks, start_pos, end_pos)
    }
}

/// Per-thread state for coverage tracking.
///
/// Holds the SHM handles that the target process writes into, and a reference
/// to the shared `GlobalBranches`.  Thread-local state (RNG, seed-insertion
/// flag) is stored here to avoid synchronisation overhead on the hot path.
pub struct Branches {
    pub global: Arc<GlobalBranches>,
    depot: Arc<Depot>,

    // SHMs shared with the fast / full / trace target processes.
    trace_map: SHM<u8>,
    full_trace_map: SHM<u8>,
    taint_trace_map: SHM<u8>,
    // Each u16 encodes branch "closeness": bits[15:10] = hit-count bucket, bits[9:0] = match value (0–1023).
    frontier_branch_map: SHM<u16>,
    cmp_trace_map: SHM<trace_data::CmpTrace>,

    // Pre-computed coprime step sizes for `random_chunk_order`.
    steps: Vec<usize>,

    // Per-execution state reset by `has_new_edge`.
    insert_seed_flag: bool,
    seed_info: SeedInfo,
    rng: ThreadRng,
}

impl Branches {
    pub fn new(global: Arc<GlobalBranches>, depot: Arc<Depot>) -> Self {
        let n = global.thread_num;
        let fast = &global.fast_map_size_data;
        let full = &global.full_map_size_data;
        let trace = &global.trace_map_size_data;

        let trace_map = SHM::<u8>::new(fast.used_map_size);
        let full_trace_map = SHM::<u8>::new(full.used_map_size);
        let taint_trace_map = SHM::<u8>::new(trace.used_map_size);
        let frontier_branch_map = SHM::<u16>::new(fast.used_branch_map_size);
        let cmp_trace_map = SHM::<trace_data::CmpTrace>::new(trace.used_branch_map_size);

        // Coprime step sizes ensure uniform coverage of all chunks regardless of starting chunk.
        let steps = if n == 1 {
            vec![1usize]
        } else {
            (1..n).filter(|&x| gcd(x, n) == 1).collect()
        };

        Self {
            global,
            depot,
            trace_map,
            full_trace_map,
            taint_trace_map,
            frontier_branch_map,
            cmp_trace_map,
            steps,
            insert_seed_flag: false,
            seed_info: SeedInfo::default(),
            rng: rand::thread_rng(),
        }
    }

    pub fn clear_trace(&mut self) { self.trace_map.clear(); }
    pub fn clear_full_trace(&mut self) { self.full_trace_map.clear(); }
    pub fn clear_taint_trace(&mut self) { self.taint_trace_map.clear(); }
    pub fn clear_frontier_branch(&mut self) { self.frontier_branch_map.clear(); }
    pub fn clear_cmp_trace(&mut self) { self.cmp_trace_map.clear(); }

    pub fn get_trace_id(&self) -> i32 { self.trace_map.get_id() }
    pub fn get_full_trace_id(&self) -> i32 { self.full_trace_map.get_id() }
    pub fn get_taint_trace_id(&self) -> i32 { self.taint_trace_map.get_id() }
    pub fn get_frontier_branch_id(&self) -> i32 { self.frontier_branch_map.get_id() }
    pub fn get_cmp_trace_id(&self) -> i32 { self.cmp_trace_map.get_id() }

    pub fn get_map_size(&self) -> usize { self.global.fast_map_size_data.used_map_size }
    pub fn get_full_map_size(&self) -> usize { self.global.full_map_size_data.used_map_size }
    pub fn get_branch_size(&self) -> usize { self.global.fast_map_size_data.used_branch_map_size }

    pub fn get_cmp_trace_copy(&self) -> Vec<trace_data::CmpTrace> {
        (*self.cmp_trace_map).to_vec()
    }

    pub fn get_trace_map_hash(&self) -> u64 {
        self.trace_map.get_hash()
    }

    pub fn get_trace_branch_type(&self, branch_id: usize) -> BranchType {
        let trace = &self.global.trace_map_size_data;
        if branch_id >= trace.real_branch_map_size && branch_id < trace.used_branch_map_size {
            // Branch ID falls in the virtual padding area — treat as ordinary Cmp.
            return BranchType::Cmp;
        }
        *self.global.trace_branch_type_dict.get(&branch_id).unwrap()
    }

    /// Returns chunk indices in a uniformly-random permutation using a coprime step.
    ///
    /// This lets each thread lock chunks in a different order, distributing
    /// contention evenly across the bitmap without starvation.
    // Returns a random permutation of chunk indices [0..n) using a coprime step walk.
    // Starting at a random index and advancing by a step that is coprime with n guarantees
    // every index is visited exactly once.  This spreads lock acquisitions across threads
    // so no two threads systematically collide on the same chunk in the same order.
    fn random_chunk_order(&mut self) -> Vec<usize> {
        let n = self.global.thread_num;
        let start = self.rng.gen_range(0..n);
        let step = self.steps[self.rng.gen_range(0..self.steps.len())];
        let mut order = Vec::with_capacity(n);
        let mut visited = vec![false; n];
        let mut idx = start;
        while order.len() < n {
            if !visited[idx] {
                visited[idx] = true;
                order.push(idx);
            }
            idx = (idx + step) % n;
        }
        order
    }

    // Reads the trace_map bitmap into a list of (local_edge_id, hit_count_bucket) pairs
    // grouped by chunk.  Uses u64-wide reads to skip zero words quickly.
    fn get_path(&self) -> Vec<Vec<(usize, u8)>> {
        let n = self.global.thread_num;
        let mut path: Vec<Vec<(usize, u8)>> = vec![Vec::new(); n];
        let buf: &[u8] = &*self.trace_map;
        let buf_u64: &[u64] = unsafe {
            std::slice::from_raw_parts(buf.as_ptr() as *const u64, buf.len() / 8)
        };
        let mut chunk = 0;
        for (i, &word) in buf_u64.iter().enumerate() {
            if word == 0 {
                continue;
            }
            let base = i * 8;
            for j in 0..8 {
                let idx = base + j;
                while idx > self.global.end_pos[chunk] {
                    chunk += 1;
                }
                let v = buf[idx];
                if v > 0 {
                    debug_assert!(chunk < n);
                    path[chunk].push((idx - self.global.start_pos[chunk], EDGE_LOOKUP[v as usize]));
                }
            }
        }
        path
    }

    // Returns raw (global_edge_id, raw_hit_count) pairs from the full-pass trace map.
    // "Raw" means no bucket mapping; used by calibrate_edge.
    pub fn get_raw_full_path(&self) -> Vec<(usize, u8)> {
        let mut result = Vec::new();
        let buf: &[u8] = &*self.full_trace_map;
        let buf_u64: &[u64] = unsafe {
            std::slice::from_raw_parts(buf.as_ptr() as *const u64, buf.len() / 8)
        };
        for (i, &word) in buf_u64.iter().enumerate() {
            if word == 0 {
                continue;
            }
            let base = i * 8;
            for j in 0..8 {
                let idx = base + j;
                let v = buf[idx];
                if v > 0 {
                    result.push((idx, v));
                }
            }
        }
        result
    }

    // Reads the full_trace_map into bucketed (local_edge_id, hit_count_bucket) pairs by chunk.
    fn get_full_path(&self) -> Vec<Vec<(usize, u8)>> {
        let n = self.global.thread_num;
        let mut path: Vec<Vec<(usize, u8)>> = vec![Vec::new(); n];
        let buf: &[u8] = &*self.full_trace_map;
        let buf_u64: &[u64] = unsafe {
            std::slice::from_raw_parts(buf.as_ptr() as *const u64, buf.len() / 8)
        };
        let mut chunk = 0;
        for (i, &word) in buf_u64.iter().enumerate() {
            if word == 0 {
                continue;
            }
            let base = i * 8;
            for j in 0..8 {
                let idx = base + j;
                while idx > self.global.full_end_pos[chunk] {
                    chunk += 1;
                }
                let v = buf[idx];
                if v > 0 {
                    debug_assert!(chunk < n);
                    path[chunk].push((idx - self.global.full_start_pos[chunk], EDGE_LOOKUP[v as usize]));
                }
            }
        }
        path
    }

    // Reads the frontier_branch_map SHM and updates branch_favor_map for every branch
    // whose match value has improved.  Inserts or replaces seeds in the depot accordingly.
    //
    // Returns (had_improvement, num_newly_covered_branches).
    fn check_frontier_branch(&mut self, buf: &Vec<u8>) -> (bool, usize) {
        let mut num_new_branches = 0;

        // Decode the frontier_branch_map into per-chunk lists.
        // Each u16 encodes: [15:10] hit-count bucket, [9:0] match value (1-1023).
        let mut per_chunk_entries: Vec<Vec<(usize, u16, u16)>> = vec![Vec::new(); self.global.thread_num];
        let mut covered_strcmp = Vec::new();

        {
            let map_buf: &[u16] = &*self.frontier_branch_map;
            let map_u64: &[u64] = unsafe {
                std::slice::from_raw_parts(map_buf.as_ptr() as *const u64, map_buf.len() / 4)
            };
            let mut chunk = 0;
            for (i, &word) in map_u64.iter().enumerate() {
                if word == 0 {
                    continue;
                }
                let base = i * 4;
                for j in 0..4 {
                    let idx = base + j;
                    while idx > self.global.branch_end_pos[chunk] {
                        chunk += 1;
                    }
                    let v = map_buf[idx];
                    if v > 0 {
                        let match_value = v & 0x3ff_u16;
                        assert!(match_value > 0);
                        let context_id = BRANCH_LOOKUP[((v >> 10) & 0x3f_u16) as usize] as u16;
                        assert!(context_id != 0);
                        self.seed_info.match_value_sum += match_value as usize;
                        per_chunk_entries[chunk].push((
                            idx - self.global.branch_start_pos[chunk],
                            context_id - 1,
                            match_value,
                        ));
                    }
                }
            }
        }

        // Read pass: identify which entries have improved match values.
        let order = self.random_chunk_order();
        let mut to_write: Vec<Vec<(usize, u16, u16)>> = vec![Vec::new(); self.global.thread_num];
        let mut any_improvement = false;

        for &ci in &order {
            if per_chunk_entries[ci].is_empty() {
                continue;
            }
            let guard = self.global.branch_favor_map[ci].read().unwrap();
            let data: &[[SeedInfo; BRANCH_CONTEXT_CNT]] = &*guard;
            for &(local_br, ctx, mv) in &per_chunk_entries[ci] {
                if data[local_br][ctx as usize].match_value < mv {
                    any_improvement = true;
                    to_write[ci].push((local_br, ctx, mv));
                }
            }
        }

        // Write pass: update branch_favor_map and depot for all improved entries.
        if any_improvement {
            self.insert_new_seed(StatusType::Normal, buf);

            let mut had_write = false;
            for &ci in &order {
                if to_write[ci].is_empty() {
                    continue;
                }

                // Update reach timestamps in branch_mutate_funcs.
                if let Ok(mut mguard) = self.global.branch_mutate_funcs[ci].write() {
                    let mdata: &mut Box<[BranchMutateInfo]> = &mut *mguard;
                    for &(local_br, _, _) in &to_write[ci] {
                        if mdata[local_br].reach_time == 0 {
                            mdata[local_br].reach_time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as usize;
                        }
                    }
                }

                let mut guard = self.global.branch_favor_map[ci].write().unwrap();
                let data: &mut [[SeedInfo; BRANCH_CONTEXT_CNT]] = &mut *guard;

                for &(local_br, ctx, mv) in &to_write[ci] {
                    if data[local_br][ctx as usize].match_value >= mv {
                        continue; // Another thread may have written a better value.
                    }

                    let real_br_id = local_br + self.global.branch_start_pos[ci];

                    if mv == 0x3ff {
                        // Max match value for strcmp-family: branch is now covered.
                        assert!(
                            self.global.branch_type_dict[&real_br_id] == BranchType::StrcmpNonTerm
                                || self.global.branch_type_dict[&real_br_id] == BranchType::ConstStrcmpNonTerm
                        );
                        covered_strcmp.push(real_br_id);
                    }

                    // Track whether this is the first context entry for this branch.
                    let is_new_frontier = data[local_br].iter().all(|e| e.seed_id == 0);
                    if is_new_frontier {
                        self.global.reached_branches.fetch_add(1, Ordering::Relaxed);
                    }

                    let prev = data[local_br][ctx as usize];
                    let is_insert = prev.seed_id == 0;
                    data[local_br][ctx as usize] = self.seed_info;
                    data[local_br][ctx as usize].match_value = mv;

                    if is_insert {
                        self.depot.branch_insert_favor_seed(self.seed_info, real_br_id, ctx as usize);
                    } else {
                        self.depot.branch_replace_favor_seed(prev, self.seed_info, real_br_id, ctx as usize);
                    }
                    had_write = true;
                }
            }
            any_improvement = had_write;
        }

        // Mark newly covered strcmp branches in global_branch_cov_map.
        if !covered_strcmp.is_empty() {
            covered_strcmp.sort();
            let mut real_covered = Vec::new();
            {
                let mut cov = self.global.global_branch_cov_map.write().unwrap();
                let data: &mut [u8] = &mut *cov;
                for branch in covered_strcmp {
                    if data[branch / 8] & (1 << (branch % 8)) != 0 {
                        continue; // Already covered.
                    }
                    data[branch / 8] |= 1 << (branch % 8);
                    self.global.cov_branches.fetch_add(1, Ordering::Relaxed);
                    num_new_branches += 1;
                    real_covered.push(branch);
                }
            }
            {
                let mut bb = self.global.branch_boundary.write().unwrap();
                for branch in real_covered {
                    bb[branch].pop();
                    assert!(bb[branch].is_empty(), "branch_boundary[{}] is not empty", branch);
                }
            }
        }

        (any_improvement, num_new_branches)
    }

    // Decrements branch_boundary for newly discovered edges and marks branches
    // whose boundary sets are now empty as covered.
    //
    // Also writes the new edges into full_virgin_branches when write_flag is true.
    // Returns the number of newly covered branches.
    pub fn update_branch_boundary(
        &mut self,
        write_flag: bool,
        _full_path: Vec<Vec<(usize, u8)>>, // caller passes this for symmetry; not needed here
        edge_to_write: Vec<Vec<(usize, u8)>>,
    ) -> usize {
        let mut new_edges = Vec::new();
        let mut num_new_branches = 0;

        if write_flag {
            let order = self.random_chunk_order();
            for &ci in &order {
                if edge_to_write[ci].is_empty() {
                    continue;
                }
                let mut guard = self.global.full_virgin_branches[ci].write()
                    .expect("full_virgin_branches RwLock poisoned");
                let data: &mut [u8] = &mut *guard;
                for &(local_edge, bucket) in &edge_to_write[ci] {
                    let gb_v = data[local_edge];
                    if (bucket & gb_v) > 0 {
                        if gb_v == 255u8 {
                            new_edges.push(self.global.full_start_pos[ci] + local_edge);
                        }
                        data[local_edge] = gb_v & !bucket;
                    }
                }
            }
        }

        // Reduce branch_boundary for each newly seen edge.
        let mut covered_branches = Vec::new();
        {
            let mut bb = self.global.branch_boundary.write()
                .expect("branch_boundary RwLock poisoned");
            for &edge in &new_edges {
                if let Some(&branch) = self.global.edge_to_pred_branch_dict.get(&edge) {
                    bb[branch].retain(|&x| x != edge);
                    assert!(bb[branch].len() <= 1);
                    if bb[branch].is_empty() {
                        covered_branches.push(branch);
                    }
                }
            }
        }

        if covered_branches.is_empty() {
            return 0;
        }

        covered_branches.sort();

        // Update the global coverage bitset.
        {
            let mut cov = self.global.global_branch_cov_map.write()
                .expect("global_branch_cov_map RwLock poisoned");
            let data: &mut [u8] = &mut *cov;
            for &branch in &covered_branches {
                if data[branch / 8] & (1 << (branch % 8)) != 0 {
                    continue; // Already marked.
                }
                data[branch / 8] |= 1 << (branch % 8);
                self.global.cov_branches.fetch_add(1, Ordering::Relaxed);
                num_new_branches += 1;
            }
        }

        // Mark branches as covered in branch_mutate_funcs.
        // Group by chunk first to minimise lock acquisitions.
        let mut per_chunk: Vec<Vec<usize>> = vec![Vec::new(); self.global.thread_num];
        for &branch in &covered_branches {
            let ci = self.global.branch_chunk_of(branch);
            per_chunk[ci].push(branch - self.global.branch_start_pos[ci]);
        }
        for ci in 0..self.global.thread_num {
            if per_chunk[ci].is_empty() {
                continue;
            }
            let mut mguard = self.global.branch_mutate_funcs[ci].write()
                .expect("branch_mutate_funcs RwLock poisoned");
            for &local_br in &per_chunk[ci] {
                mguard[local_br].is_covered = true;
            }
        }

        num_new_branches
    }

    pub fn insert_new_seed(&mut self, status: StatusType, buf: &Vec<u8>) {
        // At most one seed per coverage-check cycle.
        if !self.insert_seed_flag {
            self.insert_seed_flag = true;
            self.seed_info.seed_id = self.depot.save(status, buf);
        }
    }

    // Updates edge_favor_map: inserts or replaces the favored seed for each edge
    // reached in `path`, using (len * exec_time / match_value_sum) as the score
    // (lower is better — faster, shorter, higher match).
    fn update_edge_favor_map(&mut self, path: &Vec<Vec<(usize, u8)>>, status: StatusType, buf: &Vec<u8>) {
        let mut to_write: Vec<Vec<&(usize, u8)>> = vec![Vec::new(); self.global.thread_num];
        let order = self.random_chunk_order();

        // Read pass: identify edges whose favor seed should change.
        for &ci in &order {
            if path[ci].is_empty() {
                continue;
            }
            let guard = self.global.edge_favor_map[ci].read()
                .expect("edge_favor_map RwLock poisoned");
            let data: &[[SeedInfo; BRANCH_CONTEXT_CNT]] = &*guard;
            for br in &path[ci] {
                let pos = br.1.trailing_zeros() as usize;
                let current = &data[br.0][pos];
                if current.seed_id == 0 {
                    to_write[ci].push(br);
                } else {
                    let now_score = (self.seed_info.len * self.seed_info.exec_time_us) as f64
                        / self.seed_info.match_value_sum as f64;
                    let prev_score = (current.len * current.exec_time_us) as f64
                        / current.match_value_sum as f64;
                    if now_score < prev_score {
                        to_write[ci].push(br);
                    }
                }
            }
        }

        // Write pass: commit updates.
        for &ci in &order {
            if to_write[ci].is_empty() {
                continue;
            }
            self.insert_new_seed(status, buf);

            let mut guard = self.global.edge_favor_map[ci].write()
                .expect("edge_favor_map RwLock poisoned");
            let data: &mut [[SeedInfo; BRANCH_CONTEXT_CNT]] = &mut *guard;
            for &br in &to_write[ci] {
                let pos = br.1.trailing_zeros() as usize;
                let global_edge = br.0 + self.global.start_pos[ci];
                if data[br.0][pos].seed_id == 0 {
                    self.depot.edge_insert_favor_seed(self.seed_info, global_edge, pos);
                    data[br.0][pos] = self.seed_info;
                } else {
                    let now_score = (self.seed_info.len * self.seed_info.exec_time_us) as f64
                        / self.seed_info.match_value_sum as f64;
                    let prev_score = (data[br.0][pos].len * data[br.0][pos].exec_time_us) as f64
                        / data[br.0][pos].match_value_sum as f64;
                    if now_score < prev_score {
                        self.depot.edge_replace_favor_seed(data[br.0][pos], self.seed_info, global_edge, pos);
                        data[br.0][pos] = self.seed_info;
                    }
                }
            }
        }
    }

    // Checks whether the full-pass trace map contains any previously unseen edges.
    // Returns (has_new, full_path, edges_to_write).
    pub fn has_new_full_edge(
        &mut self,
    ) -> (bool, Vec<Vec<(usize, u8)>>, Vec<Vec<(usize, u8)>>) {
        let full_path = self.get_full_path();
        let mut to_write: Vec<Vec<(usize, u8)>> = vec![Vec::new(); self.global.thread_num];
        let mut write_flag = false;

        let order = self.random_chunk_order();
        for &ci in &order {
            if full_path[ci].is_empty() {
                continue;
            }
            let guard = self.global.full_virgin_branches[ci].read()
                .expect("full_virgin_branches RwLock poisoned");
            let data: &[u8] = &*guard;
            for &(local_edge, bucket) in &full_path[ci] {
                if (bucket & data[local_edge]) > 0 {
                    write_flag = true;
                    to_write[ci].push((local_edge, bucket));
                }
            }
        }

        (write_flag, full_path, to_write)
    }

    // Checks whether the fast-pass trace map contains any previously unseen edges.
    // Initialises insert_seed_flag and seed_info for the current cycle.
    // Returns (has_new, path, edges_to_write).
    pub fn has_new_edge(
        &mut self,
        status: StatusType,
        seed_info: SeedInfo,
    ) -> (bool, Vec<Vec<(usize, u8)>>, Vec<Vec<(usize, u8)>>) {
        self.insert_seed_flag = false;
        self.seed_info = seed_info;

        // Compute the traversal order before borrowing gb_map to avoid a
        // simultaneous mutable + immutable borrow of `self`.
        let order = self.random_chunk_order();

        let gb_map = match status {
            StatusType::Normal => &self.global.virgin_branches,
            StatusType::Timeout => &self.global.tmouts_branches,
            StatusType::Crash => &self.global.crashes_branches,
            _ => return (false, Vec::new(), Vec::new()),
        };

        let path = self.get_path();
        let edge_num: usize = path.iter().map(|v| v.len()).sum();
        self.seed_info.edge_num = edge_num;

        let n = self.global.thread_num;
        let mut to_write: Vec<Vec<(usize, u8)>> = vec![Vec::new(); n];
        let mut write_flag = false;

        for &ci in &order {
            if path[ci].is_empty() {
                continue;
            }
            let guard = gb_map[ci].read().expect("virgin bitmap RwLock poisoned");
            let data: &[u8] = &*guard;
            for &(local_edge, bucket) in &path[ci] {
                if (bucket & data[local_edge]) > 0 {
                    write_flag = true;
                    to_write[ci].push((local_edge, bucket));
                }
            }
        }

        (write_flag, path, to_write)
    }

    // Re-runs the target and compares the new path against `first_path`.
    // Marks inconsistent edges with 0xFF so they are excluded from the virgin bitmap update.
    // Returns true if any variation was found.
    pub fn calibrate_edge(
        &mut self,
        first_path: &mut Vec<Vec<(usize, u8)>>,
        edge_to_write: &mut Vec<Vec<(usize, u8)>>,
        is_full: bool,
    ) -> bool {
        let path = if is_full { self.get_full_path() } else { self.get_path() };
        let mut is_variable = false;

        for part_id in 0..first_path.len() {
            if path[part_id].is_empty() && !first_path[part_id].is_empty() {
                // All edges in this chunk disappeared — mark them all as variable.
                is_variable = true;
                for e in &mut first_path[part_id] { e.1 = 0xff; }
                for e in &mut edge_to_write[part_id] { e.1 = 0xff; }
                continue;
            }

            let mut path_ptr = 0;
            let mut write_ptr = 0;
            let mut extra = Vec::new();

            for edge in &mut first_path[part_id] {
                // Advance path_ptr past edges that only appear in the new path.
                while path_ptr < path[part_id].len() && edge.0 > path[part_id][path_ptr].0 {
                    extra.push((path[part_id][path_ptr].0, 0xff_u8));
                    is_variable = true;
                    path_ptr += 1;
                }

                if path_ptr < path[part_id].len() && edge.0 == path[part_id][path_ptr].0 {
                    if edge.1 != path[part_id][path_ptr].1 {
                        is_variable = true;
                        edge.1 = 0xff;
                        // Mark same edge in edge_to_write.
                        while write_ptr < edge_to_write[part_id].len()
                            && edge_to_write[part_id][write_ptr].0 < edge.0
                        {
                            write_ptr += 1;
                        }
                        if write_ptr < edge_to_write[part_id].len()
                            && edge_to_write[part_id][write_ptr].0 == edge.0
                        {
                            edge_to_write[part_id][write_ptr].1 = 0xff;
                        }
                    }
                    path_ptr += 1;
                } else {
                    // Edge present in first_path but not in new path.
                    is_variable = true;
                    edge.1 = 0xff;
                    while write_ptr < edge_to_write[part_id].len()
                        && edge_to_write[part_id][write_ptr].0 < edge.0
                    {
                        write_ptr += 1;
                    }
                    if write_ptr < edge_to_write[part_id].len()
                        && edge_to_write[part_id][write_ptr].0 == edge.0
                    {
                        edge_to_write[part_id][write_ptr].1 = 0xff;
                    }
                }
            }

            #[cfg(debug_assertions)]
            for e in &extra {
                assert!(
                    !first_path[part_id].iter().any(|x| x.0 == e.0),
                    "Duplicate edge {}",
                    e.0
                );
            }

            if !extra.is_empty() {
                first_path[part_id].extend_from_slice(&extra);
                edge_to_write[part_id].extend_from_slice(&extra);
                first_path[part_id].sort();
                edge_to_write[part_id].sort();
            }
        }

        is_variable
    }

    // Main coverage-update entry point called after every fast-target execution.
    //
    // Writes new edges into the virgin bitmap, updates branch frontier state, and
    // records statistics.  Returns (found_new_path, found_new_edge, edge_count, found_higher_match).
    pub fn update_edges_and_branches(
        &mut self,
        status: StatusType,
        buf: &Vec<u8>,
        local_stats: &mut LocalStats,
        mut write_flag: bool,
        path: Vec<Vec<(usize, u8)>>,
        edge_to_write: Vec<Vec<(usize, u8)>>,
        sync_flag: bool,
    ) -> (bool, bool, usize, bool) {
        // Compute the traversal order before borrowing gb_map to avoid a
        // simultaneous mutable + immutable borrow of `self`.
        let order = self.random_chunk_order();

        let gb_map = match status {
            StatusType::Normal => &self.global.virgin_branches,
            StatusType::Timeout => &self.global.tmouts_branches,
            StatusType::Crash => &self.global.crashes_branches,
            _ => return (false, false, 0, false),
        };

        let mut new_edges: Vec<usize> = Vec::new();
        let mut num_new_edge = 0;
        let mut has_new_edge = false;

        // Write new edges into the virgin bitmap.
        if write_flag {
            write_flag = false;
            for &ci in &order {
                if edge_to_write[ci].is_empty() {
                    continue;
                }
                let mut guard = gb_map[ci].write().expect("virgin bitmap RwLock poisoned");
                let data: &mut [u8] = &mut *guard;
                for &(local_edge, bucket) in &edge_to_write[ci] {
                    let gb_v = data[local_edge];
                    if (bucket & gb_v) > 0 {
                        if gb_v == 255u8 {
                            num_new_edge += 1;
                            new_edges.push(self.global.start_pos[ci] + local_edge);
                        }
                        write_flag = true;
                        if !self.insert_seed_flag {
                            self.insert_seed_flag = true;
                            self.seed_info.seed_id = self.depot.save(status, buf);
                        }
                        data[local_edge] = gb_v & !bucket;
                    }
                }
            }
        }

        if num_new_edge > 0 {
            if status == StatusType::Normal {
                self.global.cov_edges.fetch_add(num_new_edge, Ordering::Relaxed);
            }
            has_new_edge = true;
        }

        let mut has_higher_match = false;
        if status == StatusType::Normal {
            // check_frontier_branch must run before update_edge_favor_map so that
            // match_value_sum is fully accumulated in seed_info first.
            let (improved, num_new_branches) = self.check_frontier_branch(buf);
            if improved {
                local_stats.num_branches.inc(num_new_branches);
                has_higher_match = true;
            }
            self.update_edge_favor_map(&path, status, buf);
        }

        if self.insert_seed_flag || sync_flag {
            local_stats.find_new(&status);
            local_stats.num_edges.inc(num_new_edge);
        }

        if !write_flag {
            return (false, false, self.seed_info.edge_num, has_higher_match);
        }

        (true, has_new_edge, self.seed_info.edge_num, has_higher_match)
    }

    pub fn get_branch_data(&self) -> (usize, usize, usize, f32) {
        let reached = self.global.get_reached_branches();
        let (covered, total, percent) = self.global.get_branch_stats();
        (reached, covered, total, percent)
    }
}

impl std::fmt::Debug for Branches {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "")
    }
}

// Lightweight helper used only during binary inspection to read map dimensions.
// Should only be instantiated in `get_crucial_data_from_binary()` (executor.rs).
pub struct TmpBranches {
    trace_map: SHM<u8>,
    frontier_branch_map: SHM<u16>,
    map_size: usize,
}

impl TmpBranches {
    pub fn new() -> Self {
        Self {
            trace_map: SHM::<u8>::new(TMP_MAP_SIZE),
            frontier_branch_map: SHM::<u16>::new(TMP_MAP_SIZE),
            map_size: TMP_MAP_SIZE,
        }
    }

    pub fn get_trace_id(&self) -> i32 { self.trace_map.get_id() }
    pub fn get_frontier_branch_id(&self) -> i32 { self.frontier_branch_map.get_id() }
    pub fn get_map_size(&self) -> usize { self.map_size }
}
