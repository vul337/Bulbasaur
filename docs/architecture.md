# System Architecture

## Multi-threaded Fuzzing and the Chunked Global Bitmap

Multi-threading is the foundation of Bulbasaur's performance. Each fuzzer thread runs an independent fuzzing loop (execute → mutate → update) and coordinates discoveries through a **Chunked Global Bitmap**, minimising inter-thread lock contention.

**Global bitmap structure** (`GlobalBranches`):

```
global_branches: Vec<RwLock<Box<[u8]>>>
                 ────────────────────
                 N chunks, each covering a range of edge indices
```

- The total edge space is divided evenly into N chunks (one per `-j` thread).
- Each chunk has its own `RwLock`; different threads can update different chunks concurrently.
- Writes lock only one chunk (microsecond-level); reads are fully concurrent.

**Randomised traversal order** (`random_chunk_order()`): each thread walks all chunks in a random coprime-step order, preventing multiple threads from always contending on the same chunk.

**The Agent mutation function registry** is also attached to `GlobalBranches` so all threads share the same set of generated mutation functions:

```
GlobalBranches
├── global_branches: Vec<RwLock<Box<[u8]>>>       # chunked edge coverage bitmap
├── frontier_branch_map: SHM u16 array            # per-branch distance tracking
└── branch_mutate_funcs: Vec<RwLock<Option<...>>> # Agent-generated mutation functions
```

**`frontier_branch_map`** is a shared-memory array; each element is 16 bits:
- High 6 bits (bits 15–10): hit-count bucket
- Low 10 bits (bits 9–0): match value (0–1023; higher = closer to satisfying the constraint)

## Agent Mutation Function Generation Thread

A dedicated `llm_loop` thread runs in parallel with the Rust fuzzing loop:

```
Agent thread                             Python bridge
─────────────────────────────            ─────────────────────────────────────────
Scans frontier_branch_map                Receives "1 branch_id edge_id"
  → finds "hard frontier" branches       Resolves branch source location
  → sends "1 branch_id edge_id"            (ELF debug section + CSV)
  ← receives ".so path"                  Reads surrounding source context
dlopen()s the .so                        Calls Agent → generates Rust mutation function
Registers mutate_branch_N() into         cargo build --release → .so
  GlobalBranches.branch_mutate_funcs     Returns "0 branch_id /path/to/lib.so"
```

Generated mutation function contract (Rust):

```rust
#[no_mangle]
pub extern "C" fn mutate_branch_N(
    buf: *mut Vec<u8>,
    op1_substr: *const Vec<u8>,   // comparison operand 1 (observed at runtime)
    op2_substr: *const Vec<u8>,   // comparison operand 2 (target value)
) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe {
            // ... branch-specific mutation logic ...
            1  // 1=modified, 0=unchanged
        }
    })).unwrap_or(-1)  // -1=panic occurred
}
```

**ForkMutationExecutor**: to prevent Agent-generated code from crashing the fuzzer, each mutation function call runs in a forked child process with rlimits (64 MB memory, 1 CPU-second) and a 1-second wall-clock timeout.

## Branch-Distance–Guided Seed Scheduling

Bulbasaur maintains two independent seed queues and uses Thompson Sampling to adaptively choose between them:

| Queue | Contents | Selection criterion |
|-------|----------|---------------------|
| `edge_queue` | Seeds that cover new edges | AFL-style energy scheduling |
| `branch_queue` | Seeds with the highest match value for an uncovered branch | Higher match value = higher priority |

**Thompson Sampling**: each queue maintains Beta distribution parameters `(α, β)`; a sample is drawn from each to decide which queue to pick from:
- Choosing a queue that leads to new coverage → α increases (positive feedback)
- No new coverage found → β increases (negative feedback)

This makes scheduling adaptive: the queue that has been more productive recently is selected more often.

## TaintFuzz / Direct-Copy Mutation

TaintFuzz uses branch comparison operands recorded by the trace target at runtime to replace matching bytes in the input with the target value, directly "solving" branch constraints:

1. **Trace execution**: run the current seed through the trace target, recording all comparison instruction operands (`op1`, `op2`).
2. **Operand matching**: search the input buffer for occurrences of `op1` (at 1/2/4/8-byte widths).
3. **Direct-copy**: overwrite the matched bytes with `op2` (or vice versa).
4. **Agent mutation**: for branches that have a registered mutation function, also invoke `mutate_branch_N()` for targeted mutation.

Supported comparison types:
- **Cmp / ConstCmp / Switch**: integer comparisons (1/2/4/8 bytes)
- **Strcmp / ConstStrcmp**: string comparisons (up to 32 bytes)
- **Length detection**: if an operand equals the input length, push it into `len_vec` for input-size mutations

## Seed Scoring and Energy Scheduling

`calculate_score()` computes a mutation budget multiplier along two dimensions:

1. **Execution time**: shorter execution time (faster target) → more mutation rounds allocated
2. **Edge count**: more edges covered (richer code path) → more mutation rounds allocated

The score cap is controlled by the `HAVOC_MAX_MULT` configuration parameter.

## Instrumentation Pipeline

Bulbasaur uses four LLVM passes to instrument the target program at different levels, selected via the `BULBASAUR_INST_MODE` environment variable:

| Mode | Pass file | Purpose |
|------|-----------|---------|
| `FAST` | `bulbasaur-cov-fast.so` | Main fuzzing loop (pruned edge bitmap, lightweight) |
| `FULL` | `bulbasaur-cov-full.so` | Runs when a new edge is found (full bitmap, no pruning) |
| `TRACE` | `bulbasaur-cov-trace.so` | TaintFuzz phase (records comparison operands) |
| `DEBUG` | `bulbasaur-cov-debug.so` | Agent mode (embeds branch→source location mapping) |

Instrumented binaries contain the following ELF sections, read by the fuzzer at startup:

| ELF section | Contents |
|-------------|----------|
| `sancov_guards` | SanitizerCoverage edge guard address array |
| `branch_guards` | Branch guard address array |
| `branch_type` | Type of each branch (Cmp/Strcmp/Switch/…) |
| `edge_to_pred_branch` | Edge ID → predecessor branch ID mapping |
| `__debug_info` | Branch ID → source location hash (DEBUG mode) |
| `__edge_debug_info` | Edge ID → source location hash (DEBUG mode) |
