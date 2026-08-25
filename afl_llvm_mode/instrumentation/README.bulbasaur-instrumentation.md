# Bulbasaur Coverage Instrumentation Passes

This directory contains four LLVM pass-plugin shared libraries that replace
AFL++'s standard `SanitizerCoveragePCGUARD` pass in the Bulbasaur pipeline.
Each pass is compiled into a `.so` that `afl-cc` injects via `-fpass-plugin=`.

---

## Overview

```
Target source code
       │
       ▼  afl-cc / afl-c++ (with BULBASAUR_INST_MODE)
       │
   ┌───┴────────────────────────────────────────────────────┐
   │                 LLVM IR pass pipeline                  │
   │                                                        │
   │  bulbasaur-cov-full.so  – Full coverage  (default / FULL)  │
   │  bulbasaur-cov-fast.so  – Fast coverage  (FAST)            │
   │  bulbasaur-cov-debug.so – Source-loc CSV (DEBUG)           │
   │  bulbasaur-cov-trace.so – Operand trace  (TRACE)           │
   └───┬────────────────────────────────────────────────────┘
       │
       ▼  Instrumented binary
```

Select a pass by setting the **`BULBASAUR_INST_MODE`** environment variable before
invoking `afl-cc`:

| `BULBASAUR_INST_MODE` | Pass loaded           | Typical use                    |
|-------------------|-----------------------|--------------------------------|
| `FULL` (default)  | `bulbasaur-cov-full.so`   | Coverage updates after new edges |
| `FAST`            | `bulbasaur-cov-fast.so`   | High-throughput fuzzing loop   |
| `DEBUG`           | `bulbasaur-cov-debug.so`  | Offline branch-location mapping |
| `TRACE`           | `bulbasaur-cov-trace.so`  | Branch operand data collection |

Legacy single-variable env vars (`USE_FAST`, `USE_TRACE`, `USE_DEBUG`) are
still accepted for backward compatibility but are deprecated.

---

## Pass Details

### 1. `bulbasaur-cov-full.so`  —  Full Branch Coverage Pass

**Purpose:** The reference coverage pass. Instruments *every* basic block
(NoPrune=true) and records complete branch-to-edge mappings.

**What it instruments beyond vanilla AFL++:**

- **ICmp / FCmp → branch**: injects a `trace_brN()` call (N = 8/16/32/64 bits)
  with `(branch_id, val_a, val_b)`.  The runtime records `val_a XOR val_b`
  alongside the branch ID so the scheduler knows the operand distance.
- **strcmp-family → branch**: same, for `strcmp`, `strncmp`, `memcmp`,
  and common C++ `std::string` comparison operators.
- **SwitchInst**: each case arm gets its own `branch_id` so taken-case
  information is preserved.
- **ELF sections emitted** (read by the runtime at startup):
  - `sancov_guards`       – AFL++ edge counter slots
  - `branch_guards`       – branch IDs for each instrumented branch
  - `branch_type`         – `BranchType` enum value per branch
  - `edge_to_pred_branch` – maps edge-slot index → its predecessor branch ID

**When to use:** Compile the target with `BULBASAUR_INST_MODE=FULL` (or leave
unset) when you need a complete branch bitmap — for example during an initial
"coverage update" run triggered by the Fast pass detecting a new edge.

**Key env vars (runtime):**

| Variable                    | Effect                                      |
|-----------------------------|---------------------------------------------|
| `AFL_SAN_NO_INST`           | Skip all instrumentation (for debugging `afl-cc` itself) |
| `AFL_DEBUG`                 | Verbose pass output                         |
| `AFL_QUIET`                 | Suppress pass banner                        |
| `AFL_LLVM_SKIP_NEVERZERO`   | Disable never-zero counter workaround       |
| `AFL_LLVM_THREADSAFE_INST`  | Use atomic increments (multi-threaded targets) |

---

### 2. `bulbasaur-cov-fast.so`  —  Fast Branch Coverage Pass

**Purpose:** A performance-optimised variant for the high-throughput fuzzing
inner loop. It applies AFL++'s standard dominator-tree edge pruning so fewer
basic blocks are instrumented, keeping the bitmap small and execution fast.

**How it differs from the Full pass:**

- `NoPrune=false`: dominator-tree pruning is enabled for the AFL++ edge
  counter, reducing instrumented blocks and bitmap pressure.
- Uses a *two-tier* block selection:
  - `shouldInstrumentBlockNoPrune()` for branch-trace target selection (all
    blocks), ensuring branch traces fire at every comparison site.
  - `shouldInstrumentBlock()` for sancov counter placement (pruned subset),
    keeping AFL++ overhead minimal.
- The `edge_to_pred_branch` section is still emitted, so when the runtime
  detects a **new edge** it can look up the responsible branch ID and
  schedule a Full-pass re-execution for that input.

**When to use:** Default mode during fuzzing (`BULBASAUR_INST_MODE=FAST`).  
The Fast pass handles the hot path; the Full pass is invoked only on new edges.

---

### 3. `bulbasaur-cov-debug.so`  —  Source-Location Debug Pass

**Purpose:** A *compile-time-only* analysis pass that writes branch source
locations to CSV files. It does not need to run during fuzzing sessions.

**Output** (set `BULBASAUR_BRANCH_LOC_PATH=<output_dir>` before building):

```
<output_dir>/branch_loc.csv     – branch_id, file, line, col, type, function
<output_dir>/function_loc.csv  – function_name, file, line
```

**When to use:**

1. Compile the target once with `BULBASAUR_INST_MODE=DEBUG` and
   `BULBASAUR_BRANCH_LOC_PATH=/path/to/out` to generate the CSV tables.
2. Load the CSVs into the Bulbasaur analyser to translate runtime branch IDs
   (as reported by the Full/Fast passes) back to human-readable source
   locations.

The pass also instruments the binary with the same `branch_id` scheme as the
Full pass (NoPrune=true) and embeds two additional ELF sections into the
compiled binary so the Agent bridge can resolve runtime branch/edge IDs to
source locations without the CSV files:

| Section              | Contents |
|----------------------|----------|
| `__debug_info`       | Array of `(branch_guard_address, location_hash)` pairs — one per branch |
| `__edge_debug_info`  | Array of `(sancov_guard_address, location_hash)` pairs — one per edge |

`file_utils.load_branch_mapping()` in the Agent bridge reads these sections
with `pyelftools`, computes IDs from guard addresses, and resolves hashes to
`"file:line"` strings via the CSV mapping file.

**Key env vars (at compile / link time):**

| Variable                | Effect                                              |
|-------------------------|-----------------------------------------------------|
| `BULBASAUR_BRANCH_LOC_PATH` | Directory for CSV output. Silent no-op if unset.    |
| `AFL_DEBUG`             | Verbose pass output                                 |

---

### 4. `bulbasaur-cov-trace.so`  —  Branch Operand Trace Pass

**Purpose:** Records the raw operand values of every branch comparison to a
CSV file at **runtime**. Used by the seed-synthesis component to derive byte
patterns that can flip previously unseen branches.

**Output** (set `BULBASAUR_BRANCH_TRACE_PATH=<file.csv>` before running):

```
<file.csv>  – branch_id, val_a, val_b   (one row per branch execution)
```

For integer comparisons `val_a` and `val_b` are the literal operand integers.
For string comparisons they are derived metrics (length / hash).

**When to use:**

1. Run the target with `BULBASAUR_BRANCH_TRACE_PATH=/path/to/trace.csv`.
2. Feed the trace CSV into the seed synthesiser, which uses
   `(branch_id, val_a, val_b)` tuples to generate mutations that satisfy
   branch conditions.

**How it differs from the Full pass:**

- `NoPrune=false` (same as Fast pass) for consistent `branch_id` numbering
  with the Fast-pass bitmap.
- `shouldInstrumentBlockNoPrune()` is used for branch-trace selection so
  every comparison site emits a trace record.
- `trace_brN()` writes both operand values to the output file rather than
  XOR-ing them into the AFL++ bitmap.

**Key env vars (runtime):**

| Variable                 | Effect                                              |
|--------------------------|-----------------------------------------------------|
| `BULBASAUR_BRANCH_TRACE_PATH`| Path to the output CSV file. Required; pass errors out if missing. |
| `AFL_DEBUG`              | Verbose pass output                                 |

---

## Building

All four passes are built automatically by the top-level `GNUmakefile`.
LLVM ≥ 13 is required.

```bash
cd /path/to/Bulbasaur/afl_llvm_mode
make
# Produces: bulbasaur-cov-full.so  bulbasaur-cov-fast.so
#           bulbasaur-cov-trace.so  bulbasaur-cov-debug.so
```

Individual targets:

```bash
make bulbasaur-cov-full.so
make bulbasaur-cov-fast.so
make bulbasaur-cov-trace.so
make bulbasaur-cov-debug.so
```

---

## Using the Passes

```bash
# Full pass (default — used for coverage updates)
afl-cc -o target target.c

# Fast pass (high-throughput fuzzing loop)
BULBASAUR_INST_MODE=FAST afl-cc -o target_fast target.c

# Debug pass — generate branch source-location CSV
mkdir -p /tmp/branch_info
BULBASAUR_INST_MODE=DEBUG BULBASAUR_BRANCH_LOC_PATH=/tmp/branch_info \
  afl-cc -o target_debug target.c
# → /tmp/branch_info/branch_loc.csv and function_loc.csv are written

# Trace pass — collect branch operand values at runtime
BULBASAUR_INST_MODE=TRACE afl-cc -o target_trace target.c
BULBASAUR_BRANCH_TRACE_PATH=/tmp/trace.csv ./target_trace <input
# → /tmp/trace.csv populated with branch_id,val_a,val_b rows
```

---

## ELF Section Layout

### Full / Fast passes

The runtime (`afl-compiler-rt`) reads these sections at startup via the
`__sanitizer_cov_trace_pc_guard_init`-style constructor:

| Section               | Element type | Description                                  |
|-----------------------|--------------|----------------------------------------------|
| `sancov_guards`       | `uint32_t`   | AFL++ edge counter guard slot (one per block)|
| `branch_guards`       | `uint32_t`   | Branch ID for each instrumented branch        |
| `branch_type`         | `uint32_t`   | `BranchType` enum value (Cmp, Switch, …)     |
| `edge_to_pred_branch` | `uint32_t`   | Guard-slot index → predecessor branch ID     |

### Debug pass (additional sections)

Read by the Agent bridge (`file_utils.load_branch_mapping()`) to map runtime
branch/edge IDs back to source locations:

| Section              | Element type | Description                                          |
|----------------------|--------------|------------------------------------------------------|
| `__debug_info`       | `(u64, u64)` | `(branch_guard_address, location_hash)` per branch   |
| `__edge_debug_info`  | `(u64, u64)` | `(sancov_guard_address, location_hash)` per edge     |

The `branch_guards` and `edge_to_pred_branch` sections are the key Bulbasaur
additions: they let the scheduler know *which branch* is responsible for each
AFL++ edge hit, enabling targeted re-execution under the Full pass.
