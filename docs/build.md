# Build

## Dependencies

- Linux x86-64 (tested on Ubuntu 20.04 / 22.04)
- Rust stable (install via [rustup](https://rustup.rs))
- LLVM/Clang 13 (recommended; LLVM 12+ may work; LLVM 19+ is not supported)
- Python 3.10+ (Agent bridge, required for Agent mode; **optional** for basic mode)
- For the built-in `mini` harness: `python3 -m pip install -r llm_scripts/requirements.txt`
  and bubblewrap (`bwrap`); Claude Code/Codex are optional external backends.

## Build Steps

```bash
# 1. Set LLVM path
export PATH=/path/to/clang+llvm-13/bin:$PATH
export LD_LIBRARY_PATH=/path/to/clang+llvm-13/lib:$LD_LIBRARY_PATH

# 2. Build LLVM instrumentation passes
cd /path/to/Bulbasaur/afl_llvm_mode
make -j$(nproc)

# 3. Build the fuzzer
cd /path/to/Bulbasaur
cargo build --release
# Binary is at target/release/fuzzer

# 4. System configuration (same as AFL)
echo core | sudo tee /proc/sys/kernel/core_pattern
```

When building the FuzzBench adapter, its benchmark environment adds
`-stdlib=libc++` to `CXXFLAGS`, while the Linux clang driver is normally linked
against libstdc++. The Makefile deliberately compiles the dynamically loaded
Bulbasaur pass plugins with `-stdlib=libstdc++` after inherited flags so the
plugin and clang use one C++ ABI. Override `BULBASAUR_PLUGIN_STDLIB` only when
the clang toolchain itself uses a different standard library.

## Compiling Target Programs

Each target program must be compiled into four instrumented variants (basic mode requires only fast/full/trace; Agent mode also requires debug).

For autoconf projects, run `./configure` first; for cmake projects, specify the compiler during the cmake configure step (see below).

### autoconf projects

```bash
export CC=/path/to/Bulbasaur/afl_llvm_mode/afl-cc
export CXX=/path/to/Bulbasaur/afl_llvm_mode/afl-c++
./configure --disable-shared

# Fast target (main fuzzing loop)
make clean && BULBASAUR_INST_MODE=FAST make -j$(nproc)
cp <binary> targets/<program>_fast

# Full target (precise coverage tracking when a new edge is found)
make clean && BULBASAUR_INST_MODE=FULL make -j$(nproc)
cp <binary> targets/<program>_full

# Trace target (TaintFuzz comparison operand recording)
make clean && BULBASAUR_INST_MODE=TRACE make -j$(nproc)
cp <binary> targets/<program>_trace

# Debug target (Agent mode — embeds source location information)
mkdir -p /path/to/output/
make clean && BULBASAUR_INST_MODE=DEBUG BULBASAUR_BRANCH_LOC_PATH=/path/to/output/ make -j$(nproc)
cp <binary> targets/<program>_debug
```

### cmake projects

cmake bakes the compiler into the Makefile at configure time, so the compiler must be specified during `cmake` and the instrumentation mode during `make`:

```bash
CC=/path/to/Bulbasaur/afl_llvm_mode/afl-cc \
CXX=/path/to/Bulbasaur/afl_llvm_mode/afl-c++ \
cmake -DBUILD_SHARED_LIBS=OFF .

# Then for each target variant:
make clean && BULBASAUR_INST_MODE=FAST make -j$(nproc)
# ...and so on as above
```

`BULBASAUR_BRANCH_LOC_PATH` specifies the directory where `branch_loc.csv` is
written at compile time. The agent bridge uses it with the debug target to map
runtime branch IDs back to human-readable source locations; `function_loc.csv`
is not required by the agent path.
