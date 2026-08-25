# Bulbasaur Fuzzer

Coverage-guided fuzzer with branch-distance feedback, taint-guided mutation, and adaptive seed scheduling.

---

## Architecture Overview

```
fuzz_main
  ├── GlobalBranches   — shared bitmaps and branch metadata (one set per fuzzer thread)
  ├── Depot            — seed store and scheduling (branch queue + edge queue)
  └── FuzzLoop (N threads)
        └── Executor
              ├── fast target  — AFL++-style edge bitmap, runs on every input
              ├── full target  — full edge + branch bitmap, runs on new-edge inputs
              └── trace target — branch operand recorder, runs during TaintFuzz
```

### Three-Target Execution Model

Each input may be run through up to three independently instrumented binaries:

| Target | Instrumentation | When Used |
|--------|-----------------|-----------|
| **fast** | Pruned edge bitmap + frontier branch SHM | Every input execution |
| **full** | Unpruned edge + branch bitmap (NoPrune) | Only when fast target finds a new edge |
| **trace** | Branch operand recorder (cmp trace SHM) | TaintFuzz phase, once per seed selection |

The fast target uses dominator pruning (fewer edges to track) for throughput; the full target sees every edge for accurate branch boundary tracking.

---

## Core Components

### `branches.rs` — Global Coverage State

`GlobalBranches` is shared across all fuzzer threads and holds:

- **`virgin_branches`** / **`virgin_full_branches`**: chunked bitmaps tracking which edges have been seen. Chunked into `N` `RwLock<Box<[u8]>>` segments (one per thread) to reduce lock contention.
- **`frontier_branch_map`**: SHM `u16` array. Each entry encodes `[bits 15-10] = hit-count bucket, [bits 9-0] = match value (0-1023)`. Tracks how close each branch is to being satisfied.
- **`branch_mutate_funcs`**: per-branch custom mutation functions (registered by the Agent bridge).
- **`branch_start_pos`**: per-chunk start index, used for O(log n) chunk lookup via `branch_chunk_of()`.

`Branches` (per-thread) wraps `GlobalBranches` and provides:

- `has_new_edge` / `has_new_full_edge`: scans chunked bitmaps in a random coprime-step order (`random_chunk_order()`) to avoid lock starvation.
- `update_edges_and_branches`: on new edges, updates virgin bitmaps, schedules the seed into the depot's favor queues, and computes the match value for branch-distance guidance.
- `update_branch_boundary`: after a full-target run, determines which branches become fully covered based on their predicate edges.

**Hit-count bucketing** follows AFL++ conventions:
- Edge hits: 8 buckets via `EDGE_LOOKUP` — [1],[2],[3],[4-7],[8-15],[16-31],[32-127],[128+]
- Branch hits: 8 buckets via `BRANCH_LOOKUP` — [1],[2],[3],[4-6],[7-12],[13-20],[21-35],[36-63]

### `depot/depot.rs` — Seed Store and Scheduling

`Depot` maintains two independent priority queues, each wrapped in a `FavorQueue`:

- **`branch_queue`**: seeds selected because they push an uncovered branch closer to satisfied (highest match value).
- **`edge_queue`**: seeds selected because they cover an edge with good score (short input, fast execution, many edges).

Queue selection uses **Thompson Sampling** (`queue_rewards: RwLock<Vec<(usize, usize)>>`): beta distribution samples are drawn for each queue and the queue with the highest sample is chosen. Beta parameters decay over time (`TS_DECAY_FACTOR`) to discount stale history.

`FavorQueue` invariant: a seed appears in the priority queue if and only if it still has at least one `item_id` in its `favor_data` set. Lock order is always `queue` before `favor_data`.

### `executor/executor.rs` — Target Execution

`Executor` owns one forkserver per target (`forksrv`, `full_forksrv`, `trace_forksrv`) and drives execution:

1. **`run(buf)`**: writes the input, runs the fast target, calls `do_if_has_new`.
2. **`do_if_has_new`**: checks for new edges/paths; if a new edge is found, calibrates it (re-runs `CAL_TIME` times to filter variable paths), then invokes the full target to update branch boundaries.
3. **`trace_testcase(buf)`**: runs the trace target; the caller (TaintFuzz) then reads operand data from `cmp_trace_map`.
4. **`rebind_forksrv()`**: restarts all three forkservers (called after consecutive timeouts).

Inputs are delivered via file, stdin, or shared memory (`shmem_fuzz` mode). All three targets share the same delivery mechanism detected at startup.

### `search/` — Mutation Strategies

#### `search/handler.rs` — SearchHandler

Per-seed fuzzing context. Holds references to the executor and the current seed, plus data collected from the trace pass:

- `cmp_data_in_direct_copy`: operand pairs `(op1, op2)` from branch comparisons.
- `index_to_branch_dict`: branch ID for each operand pair.
- `len_vec`: candidate input lengths inferred from length comparisons.
- `const_cmp_data_vec` / `const_strcmp_data_vec`: constant operands for dictionary insertion.

`calculate_score()` computes a mutation budget multiplier (10–300) based on execution time and edge count relative to per-thread averages. Seeds that run faster or cover more edges get more mutations.

#### `search/taint.rs` — TaintFuzz

Trace-guided mutation in three phases:

1. **Trace**: runs the trace target on the current seed to populate `handler.{cmp_data_in_direct_copy, len_vec, ...}`.
2. **`len_fuzz`**: tries trimming or extending the input to lengths hinted by length-comparison operands.
3. **`direct_copy_fuzz`**: for each branch operand pair, either:
   - Calls a registered custom mutation function via `ForkMutationExecutor` (fork + SHM + rlimit, 1-second timeout), or
   - Falls back to `match_and_replace_input`: scans the input for `op1`/`op2` (and their byte-reversed forms) and replaces one with the other.

`ForkMutationExecutor` isolates custom mutation functions (e.g., Agent-generated) in a forked child with 64 MB memory limit and 1 CPU-second limit. Results are communicated via a POSIX SHM segment. Functions that timeout or crash are automatically disabled.

#### `search/afl.rs` — AFLFuzz

Standard havoc mutation with an optional UCB-scheduled variant:

- **Standard mode** (`scheduled_mutation = false`): randomly selects mutators from the full set, applies 1–`max_stacking` mutations per execution.
- **Scheduled mode** (`scheduled_mutation = true`): uses Upper Confidence Bound weighting (`value_i/total_i + sqrt(2·ln(total)/total_i)`) to prefer mutators and input positions that have historically produced interesting results. Currently disabled in practice due to limited effectiveness.

Both modes include a splice stage that crosses the current seed with a randomly chosen corpus input.

#### `search/trim.rs` — Trimming

Reduces seed size while preserving the same trace hash (fast target). Uses binary search to find the largest removable suffix/prefix, then tries chunk deletions.

#### `search/exploit.rs` — ExploitFuzz

Applies deterministic dictionary mutations: inserts or overwrites bytes at every position using entries from `const_cmp_data_vec` and `const_strcmp_data_vec` (constants seen in comparison operands).

---

## Seed Scheduling

1. `Depot::get_top_seed()` uses Thompson Sampling to pick `branch_queue` or `edge_queue`.
2. The top seed (highest priority = least recently used) is returned and its priority is advanced.
3. After the fuzzing round, `update_beta_values_in_depot(queue_id, rewards)` updates the beta parameters so productive queues are favored more.

The `queue_rewards` field in `SearchHandler` accumulates (successes, failures) for the current seed's queue, then the `FuzzLoop` writes these back to the depot after the round.

---

## Multi-Threading

Each fuzzer thread has its own `Executor` (and therefore its own forkservers and `Branches`). Shared state is:

| Component | Sharing Mechanism |
|-----------|-------------------|
| `GlobalBranches` bitmaps | `Arc<GlobalBranches>` with chunked `RwLock<Box<[u8]>>` |
| `frontier_branch_map` | Direct SHM (written by target, read by fuzzer) |
| `Depot` queues | `Arc<Depot>` with per-queue `Mutex` |
| Branch mutate funcs | `Arc<Vec<RwLock<Vec<BranchMutateFunc>>>>` |
| Global stats | `Arc<RwLock<ChartStats>>` |

Threads scan global bitmaps in a randomized coprime-step chunk order to minimize lock contention on popular chunks.

---

## Key Configuration (`bulbasaur_common::config`)

| Parameter | Description |
|-----------|-------------|
| `MAX_INPUT_LEN` | Maximum input size in bytes |
| `CAL_TIME` / `LONG_CAL_TIME` | Calibration runs for new inputs |
| `MAX_HAVOC_TIMES` | Havoc mutation budget base |
| `HAVOC_STACK_POW2` | Stacking depth: `1 << (1 + rand(0..POW2))` |
| `HAVOC_MAX_MULT` | Maximum score multiplier cap |
| `MAX_DIRECT_COPY_TIMES` | TaintFuzz direct-copy budget base |
| `TMOUT_SKIP` | Consecutive timeouts before skipping a seed |
| `TS_DECAY_FACTOR` | Thompson Sampling history decay (per round) |
| `NEW_PATH_BONUS` / `NEW_EDGE_BONUS` / `GREATER_DIST_BONUS` | Mutation budget bonuses on interesting finds |

---

## File Map

```
fuzzer/src/
├── fuzz_main.rs          — entry point: initializes state, spawns threads
├── fuzz_loop.rs          — per-thread fuzzing loop (seed selection → mutate → execute)
├── llm_loop.rs           — background thread: loads Agent mutation functions from server
├── branches.rs           — global coverage bitmaps, branch-distance tracking
├── command.rs            — CLI argument parsing and target path handling
├── parse_raw_section.rs  — parses branch-type and edge→branch ELF sections from target
├── extras.rs             — dictionary (extra) data management
├── fuzz_type.rs          — FuzzType enum (stat tracking per mutation phase)
├── depot/
│   ├── depot.rs          — seed store, FavorQueue, Thompson Sampling scheduling
│   ├── seed_info.rs      — SeedInfo struct (id, len, exec_time, edge_num)
│   ├── branch_priority.rs — BranchPriority (timestamp-based priority queue key)
│   ├── depot_dir.rs      — output directory layout
│   ├── file.rs           — file naming helpers
│   └── sync.rs           — initial seed sync from input directory
├── executor/
│   ├── executor.rs       — three-target execution, new-edge handling, calibration
│   ├── forksrv.rs        — forkserver protocol (AFL++ compatible)
│   ├── pipe_fd.rs        — file/stdin input delivery
│   ├── status_type.rs    — StatusType enum (Normal/Timeout/Crash/Error/Skip)
│   └── limit.rs          — resource limit helpers
├── search/
│   ├── handler.rs        — SearchHandler: per-seed fuzzing context and scoring
│   ├── taint.rs          — TaintFuzz: trace-guided len/direct-copy mutation
│   ├── afl.rs            — AFLFuzz: havoc + splice mutation
│   ├── afl_mutators.rs   — standard mutation operators
│   ├── afl_mutators_scheduled.rs — position-aware mutation operators (UCB mode)
│   ├── trim.rs           — input trimming
│   ├── exploit.rs        — deterministic dictionary mutation
│   └── search_server.rs  — (unused) search server stub
└── stats/
    ├── local.rs          — per-thread stats (exec count, edge count, timing)
    ├── chart.rs          — global aggregated stats
    └── show.rs           — terminal display
```
