# Bulbasaur agent bridge

The Rust fuzzer protocol and generated mutator ABI are unchanged. This directory
contains the small adapter that connects that protocol to Claude Code, Codex, or
the vendored mini-swe-agent harness. The latter is the lightweight default and
does not require installing either external CLI.

## What changed

The original project LLM client and pseudo-tool agent have been removed. `agent_cli.py` now presents one common prompt and skill contract to three supported backends: `claude` (Claude Code), `codex` (Codex), and `mini` (the vendored mini-swe-agent harness). `mini` is the default for easy local and FuzzBench use; Claude Code and Codex are recommended when available because their full coding-agent capabilities generally produce better mutators. The bridge does not silently switch to another backend if the selected CLI is missing.

When the fuzzer reaches a hard frontier it sends `1 <branch_id> <edge_id>` to
`bulbasaur_llm_bridge.py`. The bridge resolves the IDs using the debug target and
`branch_loc.csv`, reads a small local context window, then starts one read-only
agent session. The agent can inspect the source tree with its native tools and
returns a single Rust mutator (or `UNABLE_TO_BREAK_THROUGH`). The existing cargo
compiler helper builds the returned `cdylib`; the bridge replies with the `.so`
path and the unchanged fuzzer loads it.

## Files

| File | Purpose |
|---|---|
| `bulbasaur_llm_bridge.py` | Starts the fuzzer, serves the socket, resolves locations, compiles output. |
| `agent_cli.py` | Uniform Claude Code/Codex/mini process adapter, prompt construction, and output extraction. |
| `mini_harness.py` | In-project mini-swe-agent runner with bubblewrap read-only isolation. |
| `seed_enricher.py` | Initial corpus enrichment: lets an agent write generator scripts and collects candidates. |
| `skills/bulbasaur-mutator/SKILL.md` | Shared behavioral contract injected into either agent. |
| `skills/bulbasaur-seed-enrichment/SKILL.md` | Seed-generation workspace and collection contract. |
| `file_utils.py` | ELF branch/edge mapping, source snippets, and generated-file management. |
| `compilation.py` | Cargo build and exported-symbol verification for generated mutators. |

The old Python OpenAI client, pseudo-tool loop, SVF callgraph, and wllvm path are
removed. The agent reads source directly; no target rebuild is performed for a
branch request. Install the small Python dependencies and bubblewrap once for
the built-in harness:

```bash
python3 -m pip install -r llm_scripts/requirements.txt
# Debian/Ubuntu: sudo apt install bubblewrap
```

## Agent configuration

For the external backends, install and authenticate the CLI on the machine that runs this bridge. The executable must be discoverable through `PATH`; Bulbasaur does not install it:

```bash
# Node.js 18+ and npm are required for these install methods.
npm install -g @anthropic-ai/claude-code
npm install -g @openai/codex

command -v claude && claude --version
command -v codex && codex --version
```

Run `claude` once to complete its Anthropic/Claude.ai sign-in, or run `codex` once and choose **Sign in with ChatGPT**. API-key and gateway setups can instead be supplied with the environment variables below. Mutator requests use the selected CLI's native tools; seed enrichment grants write access only to its retained workspace and uses a disposable source snapshot. The bridge reports a missing executable instead of silently switching backends. See the [Claude Code setup guide](https://docs.anthropic.com/en/docs/claude-code/getting-started) and [Codex CLI quickstart](https://github.com/openai/codex#quickstart).

Codex is launched with `--dangerously-bypass-approvals-and-sandbox` by design,
so the bridge does not require a nested bubblewrap/user namespace. Run it from
a trusted workspace or outer container. Mutator prompts direct Codex to inspect
only the target source and not edit it; the bridge captures the final Rust function and
owns compilation. Seed enrichment writes only under the retained output
workspace and receives a disposable source snapshot.

Claude Code also uses `--dangerously-skip-permissions` and no `--tools`
whitelist, so it can use its full built-in tool set. `--add-dir` still identifies
the source/workspace paths. Run this mode from a trusted workspace or outer
container.

Keep credentials out of the repository and output directories:

```bash
export BULBASAUR_AGENT=mini         # mini is default; Claude Code and Codex are recommended for best results
export BULBASAUR_AGENT_API_KEY='…'
export BULBASAUR_AGENT_BASE_URL='https://your-agent-gateway.example'
export BULBASAUR_AGENT_MODEL=gpt-5.6-luna
```

`BULBASAUR_AGENT_BASE_URL` is optional when the CLI is already authenticated. The
adapter maps the key/base URL to `ANTHROPIC_*` for Claude and to a temporary Codex
provider override for Codex; the secret is passed only in the child environment and
is not written to command logs. One invocation is bounded by
`BULBASAUR_AGENT_TIMEOUT` (default 900 seconds).

The mini harness uses the configured gateway and Luna model. Each LiteLLM
request defaults to a 120-second timeout and two attempts; tune these with
`BULBASAUR_MINI_API_TIMEOUT` and `BULBASAUR_MINI_RETRY_ATTEMPTS` when needed.

An OpenAI-compatible gateway should be used with `--agent codex` or `--agent mini`; its URL is
normalized to the `/v1` API root. Claude Code requires an Anthropic-compatible
gateway (or its normal local authentication), so the two CLI modes are not
interchangeable. Model names are passed through unchanged; if a gateway does not
publish a requested model, choose one of the exact model IDs returned by its
`/v1/models` endpoint. The configured gateway exposes `gpt-5.6-luna`.

## Running

```bash
python3 bulbasaur_llm_bridge.py \
  --fuzzer target/release/fuzzer \
  --fast-target targets/program_fast \
  --full-target targets/program_full \
  --trace-target targets/program_trace \
  --debug-target targets/program_debug \
  --corpus seeds \
  --output-dir output \
  --branch-mapping targets/branch_loc.csv \
  --source-base-path /path/to/program/source \
  --agent mini --agent-model gpt-5.6-luna \
  --jobs 4 --exec-args @@
```

To enrich the corpus before the fuzzer starts, add `--seed-enrich`. The selected
backend receives the source tree and a corpus summary as context, and may create generators in
`<output>/seed_enrichment/scripts`, and writes candidates in
`<output>/seed_enrichment/candidates`. Candidate files are copied into the
new corpus after duplicate and safety checks; the original corpus is never overwritten:

```bash
python3 bulbasaur_llm_bridge.py ... \
  --agent mini --seed-enrich --exec-args -f @@
```

Use `--seed-enrich-dir PATH` to choose the generated corpus location. The agent
chooses the number of candidates based on target format and parser complexity; it
is not padded to a fixed count. The host deduplicates every file in
`<output>/seed_enrichment/candidates` and copies the candidate files into the new
corpus. The enrichment report and generator scripts are retained under
`<output>/seed_enrichment/` for inspection and reproducibility. The complete selected-agent trajectory is written
to the fuzzer output's `conversation_logs/` directory alongside mutator logs.

The debug target still needs the `__debug_info` and `__edge_debug_info` sections,
but `function_loc.csv`, a callgraph, wllvm, and a target debug rebuild are not
needed at runtime.

## Output contract

The agent must emit exactly `mutate_branch_N` with:

```rust
#[no_mangle]
pub extern "C" fn mutate_branch_N(
    buf: *mut Vec<u8>,
    op1_substr: *const Vec<u8>,
    op2_substr: *const Vec<u8>,
) -> i32
```

Only `std` and `rand = "0.8"` are available. The function must catch panics,
return `1` only after modifying the input, return `0` when no safe edit applies,
and return `-1` on a caught panic. Cargo errors are fed back to the same agent for
up to three repair attempts.
