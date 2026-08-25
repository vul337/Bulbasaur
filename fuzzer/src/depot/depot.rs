use super::*;
use crate::{executor::StatusType, extras::ExtraData};
use rand;
use bulbasaur_common::{ts_sampling, config};
use std::collections::{HashMap, HashSet};
use std::{
    fs,
    io::prelude::*,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, RwLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use priority_queue::PriorityQueue;
use rand::distributions::WeightedIndex;
use rand::prelude::*;

// ─── FavorQueue ──────────────────────────────────────────────────────────────
//
// Encapsulates one "favor" priority queue: a set of seeds ranked by when they
// were last selected, together with metadata tracking how many
// branches/edges each seed currently favors.
//
// Invariant: a seed appears in `queue` if and only if its entry in
// `favor_data` is non-empty.
//
// Lock order: always acquire `queue` before `favor_data` to avoid deadlock.

struct FavorQueue {
    queue: Mutex<PriorityQueue<SeedInfo, BranchPriority>>,
    // seed_id → set of branch/edge IDs this seed currently favors.
    favor_data: Mutex<HashMap<usize, HashSet<usize>>>,
}

impl FavorQueue {
    fn new() -> Self {
        Self {
            queue: Mutex::new(PriorityQueue::new()),
            favor_data: Mutex::new(HashMap::new()),
        }
    }

    // Insert `seed_info` as the favored seed for `item_id`.
    // If the seed is already in the queue it is not re-inserted (priority unchanged).
    fn insert(&self, seed_info: SeedInfo, item_id: usize) {
        let mut q = self.queue.lock().unwrap();
        let mut data = self.favor_data.lock().unwrap();

        #[cfg(debug_assertions)]
        if let Some(set) = data.get(&seed_info.seed_id) {
            assert!(!set.contains(&item_id), "item {} already favored by seed {}", item_id, seed_info.seed_id);
        }

        data.entry(seed_info.seed_id).or_insert_with(HashSet::new).insert(item_id);
        if q.get(&seed_info).is_none() {
            q.push(seed_info, BranchPriority::new(current_timestamp()));
        }
    }

    // Replace `pre` (previously favoring `item_id`) with `now`.
    // Removes `pre` from the queue if it no longer favors any item.
    fn replace(&self, pre: SeedInfo, now: SeedInfo, item_id: usize) {
        let mut q = self.queue.lock().unwrap();
        let mut data = self.favor_data.lock().unwrap();

        // Remove pre's favor entry for item_id.
        if let Some(set) = data.get_mut(&pre.seed_id) {
            assert!(!set.is_empty());
            assert!(set.remove(&item_id), "item {} not in favor data of seed {}", item_id, pre.seed_id);
            if set.is_empty() {
                data.remove(&pre.seed_id);
                q.remove(&pre).expect("seed missing from queue despite non-empty favor data");
            }
        } else {
            panic!("seed_id {} not found in favor_data during replace", pre.seed_id);
        }

        // Insert now's favor entry.
        #[cfg(debug_assertions)]
        if let Some(set) = data.get(&now.seed_id) {
            assert!(!set.contains(&item_id), "item {} already favored by new seed {}", item_id, now.seed_id);
        }

        data.entry(now.seed_id).or_insert_with(HashSet::new).insert(item_id);
        if q.get(&now).is_none() {
            q.push(now, BranchPriority::new(current_timestamp()));
        }
    }

    // Remove `item_id` from the favor sets of every seed in `seeds_info`.
    // Seeds with empty favor sets are removed from the queue.
    fn remove_item(&self, seeds_info: &[SeedInfo], item_id: usize) {
        let mut q = self.queue.lock().unwrap();
        let mut data = self.favor_data.lock().unwrap();

        for s in seeds_info {
            if let Some(set) = data.get_mut(&s.seed_id) {
                assert!(set.remove(&item_id), "item {} not in favor data of seed {}", item_id, s.seed_id);
                if set.is_empty() {
                    data.remove(&s.seed_id);
                    q.remove(s).expect("seed missing from queue despite non-empty favor data");
                }
            } else {
                panic!("seed_id {} not found in favor_data during remove_item", s.seed_id);
            }
        }
    }

    // Returns the current top seed (peeking, not popping) and advances its priority.
    fn peek_top(&self) -> SeedInfo {
        let mut q = self.queue.lock().unwrap();
        let (key, priority) = q
            .peek()
            .map(|(k, p)| (k.clone(), p.clone()))
            .expect("priority queue is empty");
        let next_priority = priority.branch_inc();
        q.change_priority(&key, next_priority);
        key
    }

    fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// ─── Depot ───────────────────────────────────────────────────────────────────

/// Central seed store and scheduling state.
///
/// Maintains two independent favor queues:
/// - `branch_queue`: seeds selected because they push a branch closer to covered
///   (highest match value among all contexts for that branch).
/// - `edge_queue`: seeds selected because they cover an edge efficiently
///   (lowest len × exec_time / match_value_sum score).
///
/// Queue selection uses Thompson Sampling (`queue_rewards`) so the fuzzer
/// adaptively focuses on whichever queue is currently more productive.
pub struct Depot {
    branch_queue: FavorQueue,
    edge_queue: FavorQueue,
    pub num_inputs: AtomicUsize,
    pub num_hangs: AtomicUsize,
    pub num_crashes: AtomicUsize,
    pub dirs: DepotDir,
    pub extras_data: Vec<ExtraData>,
    // Beta parameters for Thompson Sampling over the two queues: [0]=branch, [1]=edge.
    pub queue_rewards: RwLock<Vec<(usize, usize)>>,
}

impl Depot {
    pub fn new(in_dir: PathBuf, out_dir: &Path, extras_data: Vec<ExtraData>) -> Self {
        Self {
            branch_queue: FavorQueue::new(),
            edge_queue: FavorQueue::new(),
            num_inputs: AtomicUsize::new(0),
            num_hangs: AtomicUsize::new(0),
            num_crashes: AtomicUsize::new(0),
            dirs: DepotDir::new(in_dir, out_dir),
            extras_data,
            queue_rewards: RwLock::new(vec![(1, 1); 2]),
        }
    }

    // ── File I/O ──────────────────────────────────────────────────────────────

    fn save_input(status: &StatusType, buf: &Vec<u8>, num: &AtomicUsize, dir: &Path) -> usize {
        let id = num.fetch_add(1, Ordering::Relaxed) + 1; // IDs start at 1.
        trace!("Find {} th new {:?} input.", id, status);
        let path = get_file_name(dir, id);
        let mut f = fs::File::create(&path).expect("Could not save new input file.");
        f.write_all(buf).expect("Could not write seed buffer to file.");
        f.sync_all().expect("Could not sync file to disk.");
        id
    }

    pub fn save(&self, status: StatusType, buf: &Vec<u8>) -> usize {
        match status {
            StatusType::Normal => Self::save_input(&status, buf, &self.num_inputs, &self.dirs.inputs_dir),
            StatusType::Timeout => Self::save_input(&status, buf, &self.num_hangs, &self.dirs.hangs_dir),
            StatusType::Crash  => Self::save_input(&status, buf, &self.num_crashes, &self.dirs.crashes_dir),
            _ => 0,
        }
    }

    // ── Branch queue operations ───────────────────────────────────────────────

    // Insert a seed that achieves the highest match value seen for `branch_id` at `pos`.
    pub fn branch_insert_favor_seed(&self, seed_info: SeedInfo, branch_id: usize, pos: usize) {
        assert!(pos < 8);
        self.branch_queue.insert(seed_info, branch_id);
    }

    // Replace the previous best seed for `branch_id` at `pos` with a better one.
    pub fn branch_replace_favor_seed(&self, pre: SeedInfo, now: SeedInfo, branch_id: usize, pos: usize) {
        assert!(pos < 8);
        self.branch_queue.replace(pre, now, branch_id);
    }

    // Called when `branch_id` becomes fully covered: removes all seeds that
    // only favored it (so they are not re-selected unnecessarily).
    pub fn branch_covered(&self, seeds_info: &[SeedInfo], branch_id: usize) {
        self.branch_queue.remove_item(seeds_info, branch_id);
    }

    // ── Edge queue operations ─────────────────────────────────────────────────

    // Insert a seed that covers `edge_id` at hit-count bucket `pos`.
    pub fn edge_insert_favor_seed(&self, seed_info: SeedInfo, edge_id: usize, pos: usize) {
        assert!(pos < 8);
        self.edge_queue.insert(seed_info, edge_id);
    }

    // Replace the previous best seed for `edge_id` at bucket `pos`.
    pub fn edge_replace_favor_seed(&self, pre: SeedInfo, now: SeedInfo, edge_id: usize, pos: usize) {
        assert!(pos < 8);
        self.edge_queue.replace(pre, now, edge_id);
    }

    // ── Scheduling ────────────────────────────────────────────────────────────

    // Returns (queue_id, seed_info) for the next seed to fuzz.
    // Uses Thompson Sampling to choose between the branch and edge queues.
    // Falls back to the non-empty queue if TS picks an empty one.
    pub fn get_top_seed(&self) -> (usize, SeedInfo) {
        let branch_empty = self.branch_queue.len() == 0;
        let edge_empty   = self.edge_queue.len() == 0;

        let ids_values = {
            let rg = self.queue_rewards.read().unwrap();
            debug!("branch rewards: {:?}, edge rewards: {:?}", rg[0], rg[1]);
            ts_sampling::TS::new(rg.len(), rg.clone()).ts_sampling()
        };

        let dist = WeightedIndex::new(&ids_values).unwrap();
        let mut rng = thread_rng();
        match (dist.sample(&mut rng) == 0, branch_empty, edge_empty) {
            (_, true, false)  => (1, self.edge_queue.peek_top()),
            (_, false, true)  => (0, self.branch_queue.peek_top()),
            (true,  false, _) => (0, self.branch_queue.peek_top()),
            _                 => (1, self.edge_queue.peek_top()),
        }
    }

    // Updates the Thompson Sampling beta parameters for `queue_id`.
    // Applies a decay factor to all queues first to discount stale history.
    pub fn update_beta_values_in_depot(&self, queue_id: usize, beta_values: (usize, usize)) {
        let mut wg = self.queue_rewards.write().unwrap();
        for val in &mut *wg {
            val.0 = (val.0 as f64 * config::TS_DECAY_FACTOR).max(1.0) as usize;
            val.1 = (val.1 as f64 * config::TS_DECAY_FACTOR).max(1.0) as usize;
        }
        wg[queue_id].0 += beta_values.0;
        wg[queue_id].1 += beta_values.1;
    }

    // ── Misc ──────────────────────────────────────────────────────────────────

    pub fn empty(&self) -> bool {
        self.num_inputs.load(Ordering::Relaxed) == 0
    }

    pub fn next_random(&self) -> usize {
        rand::random::<usize>() % self.num_inputs.load(Ordering::Relaxed) + 1
    }

    pub fn get_input_buf(&self, id: usize) -> Vec<u8> {
        let path = get_file_name(&self.dirs.inputs_dir, id);
        read_from_file(&path)
    }

    pub fn get_branch_priority_num(&self) -> usize {
        self.branch_queue.len()
    }

    pub fn get_bit_priority_num(&self) -> usize {
        self.edge_queue.len()
    }
}
