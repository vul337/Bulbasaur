# Bulbasaur FuzzBench integration

This directory contains only the FuzzBench adapter.  It deliberately does not
vendor a second copy of Bulbasaur: the builder and runner Dockerfiles clone the
configured repository at image-build time.  Set `BULBASAUR_REPO_URL` and
`BULBASAUR_REF` in those Dockerfiles (or in a local Docker build override) for
a fork or a pinned revision.

The adapter fixes the four-target build contract used by Bulbasaur:

- `FULL` is the canonical FuzzBench target;
- `FAST`, `TRACE`, and `DEBUG` are rebuilt below `/out`;
- `DEBUG` writes `/out/debug/branch_loc.csv` using
  `BULBASAUR_BRANCH_LOC_PATH` and copies the benchmark source to
  `/out/debug/repo` for direct agent inspection;
- the bridge receives `--full-target`, `--branch-mapping`, and
  `--source-base-path`, then keeps fuzzer and agent conversations under the
  FuzzBench output corpus.

The legacy LLVM dictionary pass is enabled by default for the FuzzBench
adapter. It is built with the same C++ ABI as the clang process and writes
`/out/afl++.dict`, which the runner passes to Bulbasaur as a mutation
dictionary. Set `BULBASAUR_FUZZBENCH_DICT=0` for a known-incompatible toolchain.

FuzzBench generates the concrete Makefile rules.  From a FuzzBench checkout
that contains `fuzzers/bulbasaur`, regenerate its rules and run only the
systemd benchmark as follows:

```bash
python3 docker/generate_makefile.py docker/generated.mk
make build-bulbasaur-systemd_fuzz-link-parser
make run-bulbasaur-systemd_fuzz-link-parser
```

The FuzzBench checkout used for local testing may temporarily contain a local
`Bulbasaur/` source directory in the fuzzer context.  The files committed here
do not contain that copy and use `git clone` in both image stages.

The current workspace has no implementation named `SWTAgent`; therefore the
default is the vendored mini-swe-agent harness (`mini`).  This is the
lightweight, local harness used by the project.  Override it with
`BULBASAUR_FUZZBENCH_AGENT=codex` or `claude` when those CLIs are installed.
For mutator quality, Codex or Claude Code is recommended; keep `mini` when a small self-contained harness is more important than maximum agent capability.

Local mini-harness runs keep bubblewrap isolation enabled.  The FuzzBench
runner is different: the outer FuzzBench container is already the isolation
boundary, so its runner image explicitly sets
`BULBASAUR_MINI_ALLOW_UNSANDBOXED=1` and does not create a nested user
namespace.  If a deployment requires a second sandbox, unset that variable
and use a runtime profile that permits bubblewrap/user namespaces.

For a remote OpenAI-compatible gateway, pass `BULBASAUR_AGENT_BASE_URL`,
`BULBASAUR_AGENT_API_KEY`, and optionally `BULBASAUR_AGENT_MODEL` to the
runner.  Credentials are runtime settings and are not stored in this tree.
