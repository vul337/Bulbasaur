# Copyright 2026 Bulbasaur contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""FuzzBench adapter for the Bulbasaur agent-assisted fuzzer.

FuzzBench calls :func:`build` once in a builder image and :func:`fuzz` once in
the corresponding runner.  The benchmark is compiled four times because the
agent bridge needs fast, full, trace, and debug instrumentation.  The target
source is copied into the debug artifact so the agent can inspect it at run
time; no call-graph or wllvm step is required.
"""

from __future__ import annotations

import os
import shutil
import shlex
import subprocess
import sys
from pathlib import Path

from fuzzers import utils
from fuzzers.afl import fuzzer as afl_fuzzer


ROOT = Path(os.getenv("BULBASAUR_ROOT", "/Bulbasaur"))


def _target_name() -> str:
    configured = os.environ.get("FUZZ_TARGET", "fuzz-target")
    return os.path.basename(configured)


def _variant_environment(mode: str, output: Path, target_name: str) -> dict[str, str]:
    """Return a clean compiler environment for one instrumentation variant."""
    env = os.environ.copy()
    env.update({
        "CC": str(ROOT / "afl_llvm_mode" / "afl-cc"),
        "CXX": str(ROOT / "afl_llvm_mode" / "afl-c++"),
        "AFL_PATH": str(ROOT / "afl_llvm_mode"),
        "FUZZER_LIB": "/libBulbasaurFuzzingEngine.a",
        "BULBASAUR_INST_MODE": mode,
        "OUT": str(output),
        "FUZZ_TARGET": str(output / target_name),
        "AFL_QUIET": "1",
    })
    for legacy_name in ("USE_FAST", "USE_TRACE", "USE_DEBUG", "BRANCH_LOC_PATH"):
        env.pop(legacy_name, None)

    if mode == "DEBUG":
        env["BULBASAUR_BRANCH_LOC_PATH"] = str(output)
    else:
        env.pop("BULBASAUR_BRANCH_LOC_PATH", None)

    # The legacy dictionary pass is enabled for FuzzBench by default. Its
    # plugin is built with the same C++ ABI as clang; set
    # BULBASAUR_FUZZBENCH_DICT=0 to disable it for an incompatible toolchain.
    if mode == "FULL" and os.getenv("BULBASAUR_FUZZBENCH_DICT", "1") == "1":
        env["AFL_LLVM_DICT2FILE"] = str(output / "afl++.dict")
        env["AFL_LLVM_DICT2FILE_NO_MAIN"] = "1"
    else:
        env.pop("AFL_LLVM_DICT2FILE", None)
        env.pop("AFL_LLVM_DICT2FILE_NO_MAIN", None)
    return env


def _rebuild_variant(mode: str, output: Path, target_name: str, src: str,
                     work: str | None) -> None:
    output.mkdir(parents=True, exist_ok=True)
    env = _variant_environment(mode, output, target_name)
    with utils.restore_directory(src), utils.restore_directory(work):
        utils.build_benchmark(env=env)


def _copy_source_tree(src: str, destination: Path) -> None:
    """Make source available to the runner without copying build artifacts."""
    source = Path(src) / "systemd"
    if not source.is_dir():
        source = Path(src)
    if not source.is_dir():
        raise RuntimeError(f"benchmark source tree not found: {source}")
    def _ignore(directory: str, names: list[str]) -> set[str]:
        ignored = set()
        for name in names:
            candidate = Path(directory) / name
            # systemd contains links such as test/testdata -> .; following
            # them makes copytree recurse forever. The agent only needs the
            # real source files, so omit symlinks from the snapshot.
            if candidate.is_symlink():
                ignored.add(name)
        ignored.update(
            shutil.ignore_patterns(
                ".git", "build", "out", "*.o", "*.a", "*.so", "*.gcda", "*.gcno"
            )(directory, names)
        )
        return ignored

    shutil.copytree(
        source,
        destination,
        dirs_exist_ok=True,
        ignore=_ignore,
    )


def _bundle_rust_toolchain(build_directory: Path) -> None:
    """Bundle Cargo and its cached registry for runner-side mutator builds."""
    if os.getenv("BULBASAUR_BUNDLE_RUST_TOOLCHAIN", "1") == "0":
        return
    rustc = shutil.which("rustc")
    cargo = shutil.which("cargo")
    if not rustc or not cargo:
        raise RuntimeError("Bulbasaur build requires rustc and cargo to bundle the runtime compiler")
    sysroot = Path(subprocess.check_output([rustc, "--print", "sysroot"], text=True).strip())
    bundle = build_directory / ".bulbasaur-rust"
    bin_dir = bundle / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in ("rustc", "cargo"):
        source = sysroot / "bin" / name
        if not source.is_file():
            raise RuntimeError(f"Rust toolchain binary not found: {source}")
        shutil.copy2(source, bin_dir / name)
    shutil.copytree(sysroot / "lib", bundle / "lib", symlinks=True, dirs_exist_ok=True)
    cargo_home = Path(os.getenv("CARGO_HOME", str(Path.home() / ".cargo")))
    registry = cargo_home / "registry"
    if not registry.is_dir():
        raise RuntimeError(f"Cargo registry cache not found: {registry}")
    shutil.copytree(registry, bundle / "cargo-home" / "registry", symlinks=True, dirs_exist_ok=True)
    (bundle / "cargo-home").mkdir(parents=True, exist_ok=True)
    print(f"Bundled runtime Rust toolchain at {bundle}", flush=True)

def build(*_args) -> None:
    """Build full/fast/trace/debug targets and the fuzzer executable."""
    if not (ROOT / "afl_llvm_mode" / "afl-cc").is_file():
        raise RuntimeError(f"Bulbasaur compiler wrapper not found under {ROOT}")

    build_directory = Path(os.environ["OUT"])
    build_directory.mkdir(parents=True, exist_ok=True)
    _bundle_rust_toolchain(build_directory)
    target_name = _target_name()
    src = os.environ["SRC"]
    work = os.environ.get("WORK")

    # The base artifact is the full branch-coverage target and retains the
    # benchmark's canonical FUZZ_TARGET name expected by FuzzBench.
    _rebuild_variant("FULL", build_directory, target_name, src, work)
    for mode in ("FAST", "TRACE", "DEBUG"):
        _rebuild_variant(mode, build_directory / mode.lower(), target_name, src, work)

    debug_dir = build_directory / "debug"
    _copy_source_tree(src, debug_dir / "repo")
    branch_mapping = debug_dir / "branch_loc.csv"
    if not branch_mapping.is_file():
        raise RuntimeError(f"DEBUG instrumentation did not produce the required branch mapping: {branch_mapping}")
    mapping_rows = [line for line in branch_mapping.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(mapping_rows) <= 1:
        raise RuntimeError(f"DEBUG branch mapping is empty: {branch_mapping}; Bulbasaur requires real DEBUG guard metadata for Agent mode")

    fuzzer_binary = ROOT / "target" / "release" / "fuzzer"
    if not fuzzer_binary.is_file():
        raise RuntimeError(f"Bulbasaur fuzzer binary not found: {fuzzer_binary}")
    shutil.copy2(fuzzer_binary, build_directory / "bulbasaur")
    (build_directory / "bulbasaur").chmod(0o755)

    for required in (
        build_directory / target_name,
        build_directory / "fast" / target_name,
        build_directory / "trace" / target_name,
        build_directory / "debug" / target_name,
        debug_dir / "branch_loc.csv",
        debug_dir / "repo",
    ):
        if not required.exists():
            raise RuntimeError(f"Bulbasaur build artifact missing: {required}")


def fuzz(input_corpus: str,
         output_corpus: str,
         target_binary: str,
         flags=tuple(),
         skip=False,
         no_cmplog=False) -> None:
    """Run the bridge and retain its fuzzer/agent logs in FuzzBench output."""
    del flags, skip, no_cmplog
    target = Path(target_binary)
    out = target.parent
    target_name = target.name
    fast_target = out / "fast" / target_name
    trace_target = out / "trace" / target_name
    debug_target = out / "debug" / target_name
    source_root = out / "debug" / "repo"
    fuzzer_binary = out / "bulbasaur"
    bridge = ROOT / "llm_scripts" / "bulbasaur_llm_bridge.py"

    afl_fuzzer.prepare_fuzz_environment(input_corpus)
    os.environ["DISABLE_BPFUZZ_BIND"] = "1"
    os.environ["AFL_NO_AFFINITY"] = "1"

    command = [
        sys.executable,
        str(bridge),
        "--fuzzer", str(fuzzer_binary),
        "--fast-target", str(fast_target),
        "--full-target", str(target),
        "--trace-target", str(trace_target),
        "--debug-target", str(debug_target),
        "--corpus", input_corpus,
        "--output-dir", output_corpus,
        "--branch-mapping", str(out / "debug" / "branch_loc.csv"),
        "--source-base-path", str(source_root),
        "--agent", os.getenv("BULBASAUR_FUZZBENCH_AGENT", "mini"),
        "--agent-model", os.getenv("BULBASAUR_AGENT_MODEL", "gpt-5.6-luna"),
        "--agent-start-delay", os.getenv("BULBASAUR_AGENT_START_DELAY", "60"),
        "--agent-timeout", os.getenv("BULBASAUR_AGENT_TIMEOUT", "120"),
        "--jobs", "1",
    ]

    exec_args = shlex.split(os.getenv("BULBASAUR_FUZZBENCH_EXEC_ARGS", ""))
    if exec_args:
        command.extend(["--exec-args", *exec_args])

    dictionary = out / "afl++.dict"
    target_dictionary = Path(str(target) + ".dict")
    for candidate in (dictionary, target_dictionary):
        if candidate.is_file():
            command.extend(["--dict", str(candidate)])

    if os.getenv("BULBASAUR_FUZZBENCH_SEED_ENRICH", "0") == "1":
        command.append("--seed-enrich")

    print("[run_bulbasaur] Running command: " + " ".join(command), flush=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "llm_scripts") + os.pathsep + env.get("PYTHONPATH", "")
    env["LD_LIBRARY_PATH"] = ""
    toolchain = out / ".bulbasaur-rust"
    if (toolchain / "bin" / "cargo").is_file():
        env["BULBASAUR_RUST_TOOLCHAIN"] = str(toolchain)
        env["CARGO_HOME"] = str(toolchain / "cargo-home")
        env["RUSTC"] = str(toolchain / "bin" / "rustc")
        env["PATH"] = str(toolchain / "bin") + os.pathsep + env.get("PATH", "")
        env["CARGO_NET_OFFLINE"] = "true"
    subprocess.check_call(command, env=env)
