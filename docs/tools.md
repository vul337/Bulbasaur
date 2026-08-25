# Tools

## branch_analyser

**Source**: `fuzzer/src/bin/branch_analyser.rs`

Analyses branch coverage for a given corpus and saves the results to the specified output directory. Typically used to evaluate how much of the target program the initial seed corpus covers before a fuzzing session, or to measure final branch coverage after fuzzing completes.

### Build

```bash
cd /path/to/Bulbasaur
cargo build --release --bin branch_analyser
# Binary is at target/release/branch_analyser
```

### Usage

```bash
target/release/branch_analyser \
    -i /path/to/corpus \
    -o /path/to/output \
    -f targets/<program>_full \
    -t targets/<program>_trace \
    -- targets/<program>_fast @@
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-i` / `--input` | Corpus directory containing all seed files to analyse |
| `-o` / `--output` | Output directory (**must not exist**; created automatically) |
| `-f` / `--full` | Path to the full-instrumented target binary |
| `-t` / `--trace` | Path to the trace-instrumented target binary |
| `-M` / `--memory_limit` | Memory limit for the target in MB (**optional**, default 200; set to 0 for unlimited) |
| `-T` / `--time_limit` | Execution timeout in ms (**optional**, auto-detected by default) |
| `--` | Separator; everything after is the fast target and its arguments; `@@` is the input file placeholder |

### Output

Results are written to the directory specified by `-o`, containing per-seed branch coverage data. These can be used for further analysis or comparison against fuzzing results.

---

## test_mutation_function

**Source**: `fuzzer/src/bin/test_mutation_function.rs`

Loads and tests an Agent-generated mutation function `.so` file. Use this to verify that a generated mutation function can be loaded, called, and processes inputs correctly before integrating it into the fuzzer — useful for diagnosing compilation or runtime issues.

### Build

```bash
cd /path/to/Bulbasaur
cargo build --release --bin test_mutation_function
# Binary is at target/release/test_mutation_function
```

### Usage

```bash
# Specify branch_id explicitly
target/release/test_mutation_function /path/to/libmut_branch_378.so 378

# Auto-extract branch_id from the filename (filename must contain "branch_<id>")
target/release/test_mutation_function /path/to/libmut_branch_378.so
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `<so_path>` | Path to the compiled mutation function `.so` file |
| `[branch_id]` | Branch ID (**optional**; extracted from the filename if omitted) |

### Output

- Success: prints `✓ Test completed successfully!`, exits with code 0
- Failure: prints `✗ Test failed: <error message>`, exits with code 1

### Typical use case

If the fuzzer fails to load a `.so` produced by the Agent bridge, use this tool to reproduce the issue in isolation:

```bash
# Check whether an Agent-generated mutation function loads and executes correctly
target/release/test_mutation_function output/mut_funcs/42/<timestamp>/libmut_branch_42.so 42
```
