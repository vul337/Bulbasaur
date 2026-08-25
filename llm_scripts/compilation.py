#!/usr/bin/env python3
"""
Compilation utilities for the Bulbasaur Agent Bridge.

This module contains functions for compiling Rust code to shared libraries.

Key robustness features:
- A *shared* cargo target directory so dependencies (e.g. `rand`) are compiled
  only once across all branches, cutting per-branch build time from ~10s to ~1s
  and keeping disk usage bounded (no more one full `target/` per generation).
- The produced `.so` is copied next to its `lib.rs` (a per-generation timestamped
  directory), so each load path is unique and `dlopen` never returns a cached old
  library.
- Pre-build *ABI verification*: cargo returning 0 does NOT guarantee the
  library can safely be called by the fuzzer. A Rust function can export the
  expected name while still using an incompatible C ABI. We reject anything
  other than the exact three-argument `*mut Vec<u8>, *const Vec<u8>,
  *const Vec<u8>` signature before invoking cargo and feed the error into the
  existing agent repair loop.
- Post-build *symbol verification*: cargo returning 0 does NOT guarantee the
  library is usable. If the Agent misnames the function or drops `#[no_mangle]`,
  the build still succeeds but the fuzzer's `dlsym(mutate_branch_N)` fails at
  runtime, silently wasting the whole generation. We verify the exported symbol
  here and, when missing, surface a synthetic error that flows into the existing
  Agent fix-compilation loop.
"""

import os
import re
import shutil
import subprocess
from typing import Tuple, Optional


def precheck_rust_source(rust_code: str, branch_id: int) -> Optional[str]:
    """
    Cheap static check before invoking cargo. Catches silent-failure causes
    (missing #[no_mangle], wrong function name, and an incompatible FFI
    signature) without paying for a full compile.

    Returns:
        None if the source looks OK, otherwise a human-readable error string
        formatted like a compiler error so it can be fed into fix_compilation_error.
    """
    expected_fn = f"mutate_branch_{branch_id}"

    if expected_fn not in rust_code:
        return (
            f"error: required function `{expected_fn}` is not defined in the source. "
            f"The function MUST be named exactly `{expected_fn}` so the fuzzer can "
            f"locate it by name via dlsym."
        )

    # Require a #[no_mangle] somewhere before the expected function. Without it the
    # symbol is Rust-mangled and dlsym(mutate_branch_N) fails at load time.
    fn_pos = rust_code.find(f"fn {expected_fn}")
    if fn_pos == -1:
        # `mutate_branch_N` present but not as a function definition.
        return (
            f"error: `{expected_fn}` appears in the source but not as a function "
            f"definition (`fn {expected_fn}(...)`)."
        )
    preceding = rust_code[:fn_pos]
    if "#[no_mangle]" not in preceding:
        return (
            f"error: `#[no_mangle]` attribute is missing before `fn {expected_fn}`. "
            f"Without it the exported symbol is mangled and cannot be found at runtime. "
            f"Add `#[no_mangle]` immediately above the function definition."
        )

    # The fuzzer loads the symbol as:
    #   extern "C" fn(*mut Vec<u8>, *const Vec<u8>, *const Vec<u8>) -> i32
    # A mismatched signature can still compile and export the right symbol,
    # but calling it is undefined behaviour. Keep this deliberately strict so
    # an agent's common raw-pointer `(data, len, max_len, ...)` variant is sent
    # through the normal compile-error repair loop instead of being accepted.
    signature = re.search(
        rf"pub\s+extern\s+\"C\"\s+fn\s+{re.escape(expected_fn)}\s*\((.*?)\)\s*->\s*i32",
        rust_code,
        flags=re.DOTALL,
    )
    if signature is None:
        return (
            f"error: could not parse the required signature for `{expected_fn}`. "
            f"It MUST be `#[no_mangle] pub extern \"C\" fn {expected_fn}("
            f"buf: *mut Vec<u8>, op1_substr: *const Vec<u8>, "
            f"op2_substr: *const Vec<u8>) -> i32`."
        )

    params = [
        re.sub(r"\s+", " ", item.strip())
        for item in signature.group(1).split(",")
        if item.strip()
    ]
    expected_types = ("*mut Vec<u8>", "*const Vec<u8>", "*const Vec<u8>")
    if len(params) != 3 or any(
        expected_type not in param
        for param, expected_type in zip(params, expected_types)
    ):
        return (
            f"error: `{expected_fn}` has an incompatible ABI. The fuzzer calls "
            f"exactly three arguments and requires this exact signature: "
            f"`#[no_mangle] pub extern \"C\" fn {expected_fn}("
            f"buf: *mut Vec<u8>, op1_substr: *const Vec<u8>, "
            f"op2_substr: *const Vec<u8>) -> i32`. "
            f"Do not use data/len/max_len or any extra length arguments."
        )
    return None


def _verify_exported_symbol(so_path: str, branch_id: int) -> Optional[str]:
    """
    Confirm the compiled .so actually exports `mutate_branch_{branch_id}` as a
    defined dynamic symbol. Uses `nm -D --defined-only`, falling back to
    `objdump -T`. If neither tool is available, we skip the check (return None)
    rather than block compilation.

    Returns:
        None if the symbol is present (or no tool available to check),
        otherwise a synthetic compiler-style error string.
    """
    expected_fn = f"mutate_branch_{branch_id}"

    def _run(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                return r.stdout
        except (FileNotFoundError, subprocess.SubprocessError):
            return None
        return None

    out = _run(["nm", "-D", "--defined-only", so_path])
    if out is None:
        out = _run(["objdump", "-T", so_path])
    if out is None:
        # No symbol-inspection tool available; don't block.
        print("[compile] Warning: nm/objdump not available, skipping symbol verification")
        return None

    # A defined exported symbol shows up as a word boundary match. nm marks code
    # symbols 'T'/'t'/'W'; objdump -T lists them in the dynamic symbol table.
    if re.search(rf'\b{re.escape(expected_fn)}\b', out):
        return None

    return (
        f"error: the compiled library does not export the symbol `{expected_fn}`. "
        f"This usually means the function is misnamed or `#[no_mangle]` is missing. "
        f"Ensure the function is defined exactly as "
        f"`#[no_mangle] pub extern \"C\" fn {expected_fn}(...)`."
    )


def _shared_target_dir(branch_dir: str) -> str:
    """
    Derive a stable, shared cargo target directory from a per-generation
    branch_dir of the form `<output>/mut_funcs/<branch_id>/<timestamp>`.
    The shared target lives at `<output>/mut_funcs/.cargo_target`.
    """
    mut_funcs_dir = os.path.dirname(os.path.dirname(os.path.abspath(branch_dir)))
    return os.path.join(mut_funcs_dir, ".cargo_target")


def compile_rust_to_so(branch_dir: str, branch_id: int) -> Tuple[Optional[str], Optional[str]]:
    """
    Compile Rust code in branch_dir to a shared library (.so file).

    Args:
        branch_dir: Directory containing the Rust code (lib.rs) (str)
        branch_id: Branch ID (int)

    Returns:
        Tuple of (so_path: Optional[str], error_message: Optional[str])
        - so_path: Path to a unique, loadable .so file if successful, None otherwise
        - error_message: Error message if compilation/verification failed, None otherwise
    """
    try:
        lib_rs_path = os.path.join(branch_dir, "lib.rs")

        # ---- Cheap static pre-check (catches misnamed fn / missing #[no_mangle]) ----
        try:
            with open(lib_rs_path, "r", encoding="utf-8", errors="ignore") as f:
                rust_code = f.read()
            pre_err = precheck_rust_source(rust_code, branch_id)
            if pre_err:
                print(f"[compile] Static pre-check failed: {pre_err}")
                return None, pre_err
        except FileNotFoundError:
            return None, f"lib.rs not found in {branch_dir}"

        # ---- Cargo.toml ----
        cargo_toml_path = os.path.join(branch_dir, "Cargo.toml")
        cargo_toml_content = f"""[package]
name = "mut_branch_{branch_id}"
version = "0.1.0"
edition = "2021"

[lib]
name = "mut_branch_{branch_id}"
path = "lib.rs"
crate-type = ["cdylib"]

[dependencies]
rand = "0.8"
"""
        with open(cargo_toml_path, "w", encoding="utf-8") as f:
            f.write(cargo_toml_content)

        # ---- Shared target dir: build deps once, bound disk usage ----
        shared_target = _shared_target_dir(branch_dir)
        os.makedirs(shared_target, exist_ok=True)
        env = dict(os.environ)
        env["CARGO_TARGET_DIR"] = shared_target

        print(f"Compiling Rust code in {branch_dir} (shared target: {shared_target})...")
        cargo_bin = "cargo"
        bundled_toolchain = os.getenv("BULBASAUR_RUST_TOOLCHAIN")
        if bundled_toolchain:
            candidate = os.path.join(bundled_toolchain, "bin", "cargo")
            if os.path.isfile(candidate):
                cargo_bin = candidate
                env["PATH"] = os.path.join(bundled_toolchain, "bin") + os.pathsep + env.get("PATH", "")
                env["CARGO_HOME"] = os.getenv("CARGO_HOME", os.path.join(bundled_toolchain, "cargo-home"))
                env["RUSTC"] = os.path.join(bundled_toolchain, "bin", "rustc")
                env["CARGO_NET_OFFLINE"] = "true"
        result = subprocess.run(
            [cargo_bin, "build", "--release", "--manifest-path", cargo_toml_path, "--offline"],
            capture_output=True,
            text=True,
            cwd=branch_dir,
            env=env,
        )

        if result.returncode != 0:
            error_msg = result.stderr if result.stderr else result.stdout
            print("Compilation failed:")
            print(error_msg)
            return None, error_msg

        # ---- Locate built .so in the shared target ----
        so_name = f"libmut_branch_{branch_id}.so"
        built_so = os.path.join(shared_target, "release", so_name)
        if not os.path.exists(built_so):
            target_release = os.path.join(shared_target, "release")
            listing = os.listdir(target_release) if os.path.exists(target_release) else []
            return None, (
                f"Compiled .so not found at {built_so}. "
                f"Files in release dir: {listing}"
            )

        # ---- Copy out to a unique path so dlopen never serves a cached library ----
        # branch_dir is already per-generation timestamped, so this path is unique.
        local_so = os.path.join(branch_dir, so_name)
        try:
            shutil.copy2(built_so, local_so)
        except Exception as e:
            # Fall back to the shared path; less ideal for dlopen caching but still loadable.
            print(f"[compile] Warning: failed to copy .so into branch_dir ({e}), using shared path")
            local_so = built_so

        # ---- Authoritative symbol verification ----
        sym_err = _verify_exported_symbol(local_so, branch_id)
        if sym_err:
            print(f"[compile] Symbol verification failed: {sym_err}")
            return None, sym_err

        print(f"Successfully compiled and verified {local_so}")
        return local_so, None

    except FileNotFoundError:
        error_msg = "cargo not found. Please install Rust toolchain."
        print(f"Error: {error_msg}")
        return None, error_msg
    except Exception as e:
        error_msg = f"Error during compilation: {e}"
        print(error_msg)
        import traceback
        traceback.print_exc()
        return None, error_msg
