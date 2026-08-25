# Usage

## Basic Mode (without Agent)

Basic mode can run the core fuzzer without generating branch-specific mutators.
To use the mutator-generation workflow described below, use an authenticated
Claude Code/Codex CLI or the built-in `mini` harness. The built-in harness needs
the Python dependencies in `llm_scripts/requirements.txt` and the `bwrap`
executable, but no external agent CLI.

```bash
/path/to/Bulbasaur/target/release/fuzzer \
    -i /path/to/seeds \
    -o /path/to/output \
    -j 4 \
    -b 0 \
    -M 0 \
    -f targets/<program>_full \
    -t targets/<program>_trace \
    -x dict/<program>.dict \
    -- targets/<program>_fast @@
```

| Parameter | Description |
|-----------|-------------|
| `-i` | Initial seed corpus directory |
| `-o` | Output directory |
| `-j` | Number of parallel threads |
| `-b` | CPU core to bind to (**optional**) |
| `-M` | Sync mode (`0` = primary node) (**optional**, used for multi-instance coordination) |
| `-f` | Path to the full-instrumented target binary |
| `-t` | Path to the trace-instrumented target binary |
| `-x` | Dictionary file; can be specified multiple times (**optional**) |
| `--` | Separator; everything after is the fast target and its arguments; `@@` is the input file placeholder |

## Agent Mode

Agent mode is the only mode that generates and loads branch-specific mutators.
Choose an external CLI (`claude` or `codex`) or the in-project `mini` harness.
When using a gateway, provide the corresponding `BULBASAUR_AGENT_*` environment
variables.

### Installing and authenticating external CLIs

The external backends are ordinary command-line programs. Install them on the machine that runs the bridge, make sure their executables are on `PATH`, and complete their first-run authentication before starting Bulbasaur:

```bash
# Node.js 18+ and npm are required for these install methods.
npm install -g @anthropic-ai/claude-code
npm install -g @openai/codex

command -v claude
command -v codex
claude --version
codex --version
```

Run `claude` once and finish the Anthropic/Claude.ai sign-in flow. Run `codex` once and choose **Sign in with ChatGPT**, or configure the OpenAI API key described in the Codex documentation. The bridge then invokes the selected executable non-interactively (`claude --print` or `codex exec`) with the shared Bulbasaur skill. Mutator requests use the selected CLI's native tools; seed enrichment writes only to its retained workspace and uses a disposable source snapshot. It does not install either CLI, and it does not fall back to another backend when the selected executable is missing.

Codex is launched with `--dangerously-bypass-approvals-and-sandbox` by design.
This avoids requiring a nested bubblewrap/user namespace, which is unavailable
on some hosts. Run Bulbasaur from a trusted workspace or outer container. The
mutator prompt directs Codex to inspect only the target source and not edit it;
this is a prompt-level restriction, while the bridge owns generated-code output
and compilation. Seed enrichment writes under its retained output workspace and reads a disposable source snapshot.

Claude Code also uses `--dangerously-skip-permissions` and no `--tools`
whitelist, so it can use its full built-in tool set. `--add-dir` still identifies
the source/workspace paths. Run this mode from a trusted workspace or outer
container.

For a compatible gateway instead of the vendor login, set `BULBASAUR_AGENT_API_KEY`, `BULBASAUR_AGENT_BASE_URL`, and `BULBASAUR_AGENT_MODEL`; the bridge passes those values to the selected CLI process without writing the key to logs. See the [Claude Code setup guide](https://docs.anthropic.com/en/docs/claude-code/getting-started) and [Codex CLI quickstart](https://github.com/openai/codex#quickstart) for vendor-specific installation and authentication details.

### Agent backend migration

The legacy self-implemented LLM client and pseudo-tool loop are no longer part of Bulbasaur. The bridge now supports Claude Code, Codex, and the vendored mini-swe-agent harness through one common prompt and skill contract. `mini` is the default lightweight backend and is convenient for a zero-install setup; Claude Code and Codex are recommended for stronger coding-agent results when their CLIs are installed and authenticated. The Rust fuzzer protocol and generated-mutator ABI remain unchanged.

```bash
# External Claude Code/Codex are optional when using mini. For a compatible
# gateway, keep the credential in the environment; it is never written to output.
export BULBASAUR_AGENT="mini"         # mini is default; Claude Code and Codex are recommended for best results
export BULBASAUR_AGENT_API_KEY="your-api-key"
export BULBASAUR_AGENT_BASE_URL="https://your-agent-gateway.example"
export BULBASAUR_AGENT_MODEL="gpt-5.6-luna"
# export BULBASAUR_MINI_API_TIMEOUT=120
# export BULBASAUR_MINI_RETRY_ATTEMPTS=2

python3 /path/to/Bulbasaur/llm_scripts/bulbasaur_llm_bridge.py \
    --fuzzer      target/release/fuzzer \
    --fast-target  targets/<program>_fast \
    --full-target  targets/<program>_full \
    --trace-target targets/<program>_trace \
    --debug-target targets/<program>_debug \
    --corpus       seeds/ \
    --output-dir   output/ \
    --branch-mapping targets/branch_loc.csv \
    --source-base-path /path/to/target/src \
    --agent codex --agent-model gpt-5.6-luna \
    --dict         dict/<program>.dict \
    --jobs 4 --cpu-id 0 \
    --exec-args @@
```

The bridge script automatically starts the fuzzer, establishes a TCP socket, and
handles all Agent mutation requests end-to-end. It now fails before launching the
fuzzer if the selected Agent CLI is not installed. See
[`llm_scripts/README.md`](../llm_scripts/README.md) for details.

| Parameter | Description |
|-----------|-------------|
| `--fuzzer` | Path to the fuzzer executable |
| `--fast-target` | Path to the fast-instrumented target binary |
| `--full-target` | Path to the full-instrumented target binary |
| `--trace-target` | Path to the trace-instrumented target binary |
| `--debug-target` | Path to the debug-instrumented target binary (contains branch location info) |
| `--corpus` | Initial seed corpus directory |
| `--output-dir` | Output directory |
| `--branch-mapping` | Branch → source location mapping file (`branch_loc.csv`) |
| `--source-base-path` | Root directory of the target program's source code |
| `--agent` | Agent backend: `claude`, `codex`, or `mini` (default `mini`) |
| `--agent-model` | Model passed to the agent CLI (default `gpt-5.6-luna`) |
| `--agent-timeout` | Per-request agent timeout in seconds (default `900`) |
| `--agent-skill` | Shared agent skill file (defaults to `llm_scripts/skills/bulbasaur-mutator/SKILL.md`) |
| `--dict` | Dictionary file (**optional**) |
| `--jobs` | Number of parallel threads (**optional**, default 1) |
| `--cpu-id` | CPU core to bind to (**optional**, default 0) |
| `--exec-args` | Arguments passed to the target program; `@@` is the input file placeholder |
| `--seed-enrich` | Run the selected agent for initial corpus enrichment before fuzzing |
| `--seed-enrich-dir` | Output directory for the enriched corpus (default `<corpus>.enriched`) |

The agent reads the target source tree directly with its native read/search tools.
During `--seed-enrich`, it chooses the number of seeds from the target format and
parser complexity; simple targets stay small while complex formats receive more
structural variants. There is no fixed seed-count quota.
There is no wllvm build, SVF callgraph, or legacy Python model client in this path. The
bridge still compiles the returned Rust mutator and speaks the same socket/ABI
protocol to the unchanged Rust fuzzer.

### Initial corpus enrichment

With `--seed-enrich`, the bridge first copies the original corpus to a new
directory and starts the selected agent. The `mini` backend uses the vendored
harness; `codex` and `claude` use their installed CLIs. The seed agent may inspect
the source and the corpus summary, then write generator scripts plus complex candidates
under the output directory at `seed_enrichment/` (the agent uses its current
working directory for `candidates/` and `scripts/`). Each candidate is hashed and copied to the enriched corpus.
The original corpus and the retained `seed_enrichment/` workspace are left intact.
The seed-agent trajectory is stored under the fuzz output directory at
`conversation_logs/`, just like later mutator conversations.
