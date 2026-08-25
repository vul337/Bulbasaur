#!/usr/bin/env python3
"""Run Claude Code, Codex, or the vendored mini-swe-agent mutator.

The fuzzer-facing protocol remains in ``bulbasaur_llm_bridge.py``.  This module is
deliberately a small process adapter: the agent gets a source tree and a focused
prompt, while compilation and ``dlopen`` stay in the existing bridge/fuzzer path.
No OpenAI-compatible Python client, wllvm, SVF, or custom callgraph protocol is
needed.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional


SKILL_PATH = Path(__file__).with_name("skills") / "bulbasaur-mutator" / "SKILL.md"


def _read_skill() -> str:
    return SKILL_PATH.read_text(encoding="utf-8")


def _clean_location(location: str) -> str:
    return location.replace("\\", "/")


def _extract_result(text: str, branch_id: int) -> Optional[str]:
    """Extract a sentinel or a complete Rust function from CLI final output."""
    if not text:
        return None
    if "UNABLE_TO_BREAK_THROUGH" in text:
        # The sentinel is accepted only if no function was emitted alongside it.
        if not re.search(rf"mutate_branch_{branch_id}\s*\(", text):
            return None

    # Prefer a fenced Rust block, then any fenced block containing the required fn.
    fenced = re.findall(r"```(?:rust|rs)?\s*(.*?)```", text, flags=re.IGNORECASE | re.DOTALL)
    candidates = fenced + [text]
    expected = f"mutate_branch_{branch_id}"
    for candidate in candidates:
        if expected not in candidate or "fn" not in candidate:
            continue
        # Keep the complete function and any imports/attributes in the candidate;
        # compilation precheck and cargo will reject genuinely incomplete output.
        return candidate.strip()
    return None


class AgentCLI:
    """Uniform external-agent or project-local mini harness invocation."""

    def __init__(
        self,
        base_source_path: Optional[str] = None,
        agent: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
        skill_path: Optional[str] = None,
    ):
        configured_base_url = os.getenv("BULBASAUR_AGENT_BASE_URL")
        selected = (agent or os.getenv("BULBASAUR_AGENT", "mini")).lower()
        if selected not in {"claude", "codex", "mini"}:
            raise ValueError("agent must be one of: claude, codex, mini")
        if selected == "mini":
            from mini_harness import mini_available
            if not mini_available():
                raise FileNotFoundError(
                    "vendored mini-swe-agent is unavailable; install "
                    "llm_scripts/requirements.txt and configure bubblewrap "
                    "(bwrap) user namespaces"
                )
        elif not self._which(selected):
            raise FileNotFoundError(f"Agent executable not found: {selected}")
        self.agent = selected
        self.model = model or os.getenv("BULBASAUR_AGENT_MODEL")
        self.api_key = os.getenv("BULBASAUR_AGENT_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        self.base_url = configured_base_url
        self.timeout = timeout or int(os.getenv("BULBASAUR_AGENT_TIMEOUT", "900"))
        self.base_source_path = os.path.abspath(base_source_path or os.getcwd())
        self.skill_path = Path(skill_path) if skill_path else SKILL_PATH
        self.last_request: Optional[dict] = None

    @staticmethod
    def _which(name: str) -> Optional[str]:
        for directory in os.getenv("PATH", "").split(os.pathsep):
            candidate = Path(directory) / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return None

    def _prompt(
        self,
        branch_id: int,
        edge_id: int,
        branch_location: str,
        branch_context: str,
        branch_start_line: int,
        branch_end_line: int,
        edge_location: str,
        edge_context: str,
        edge_start_line: int,
        edge_end_line: int,
        branch_function_name: Optional[str] = None,
        previous_code: Optional[str] = None,
        compile_error: Optional[str] = None,
    ) -> str:
        skill = self.skill_path.read_text(encoding="utf-8")
        prior = ""
        if previous_code:
            prior += "\n\n=== PREVIOUS MUTATOR (improve it; do not blindly repeat it) ===\n```rust\n"
            prior += previous_code
            prior += "\n```"
        if compile_error:
            prior += "\n\n=== CARGO ERROR TO FIX ===\n" + compile_error[:12000]
        return f"""{skill}

You are working in the source tree: {self.base_source_path}
Use native read/search tools on that tree if more context is needed. Absolute paths
are preferred. Restrict searches to that tree (never scan `/home/wangyy` broadly),
do not inspect unrelated repositories, do not edit any files, and do not run a build.

=== CURRENT TASK ===
Branch id: {branch_id}
Target edge id: {edge_id}
Branch function (from instrumentation): {branch_function_name or '<anonymous>'}
Branch location: {_clean_location(branch_location)}
Branch context (lines {branch_start_line}-{branch_end_line}):
```c
{branch_context}
```

Edge location: {_clean_location(edge_location)}
Edge context (lines {edge_start_line}-{edge_end_line}):
```c
{edge_context}
```

The current corpus already reaches the branch, but not the edge. The fuzzer passes
the current comparison operands as `op1_substr` and `op2_substr`; they are little-
endian byte vectors unless the source clearly requires another representation.
The target is already launched with fixed arguments and an input-file placeholder.
The branch and edge windows above are only a starting point. If this is a
non-trivial parser or helper path, inspect the enclosing function, the relevant
helper definition and one caller/callee, then the relevant headers/constants/
structures and the target fuzz harness or input-file handling. For a non-trivial
path, make at least five separate focused source-query turns and no more than ten
before the final submission; the final submission command does not count. Do not
generate the mutator until the input layout, offset, length, encoding, endianness,
and bounds are supported by source evidence. A
single query is acceptable for a direct input-local comparison whose layout is
already unambiguous; avoid broad repository scans.
{prior}

After inspecting the source, output only the requested mutator or the exact
UNABLE_TO_BREAK_THROUGH token. The required function name is mutate_branch_{branch_id}.
"""

    def _command(self, prompt: str, result_file: Path) -> list[str]:
        if self.agent == "claude":
            cmd = [
                "claude", "--print", "--output-format", "text",
                "--no-session-persistence", "--dangerously-skip-permissions",
                "--add-dir", self.base_source_path,
                "--append-system-prompt", self.skill_path.read_text(encoding="utf-8"),
            ]
            if self.model:
                cmd.extend(["--model", self.model])
            cmd.append(prompt)
            return cmd

        # Codex is intentionally run without its nested sandbox. Bulbasaur is
        # commonly launched inside a trusted fuzzing workspace/container, and
        # requiring Codex's bubblewrap user namespace prevents it from starting
        # on restricted hosts. The prompt directs mutator requests to inspect
        # only the target source and not edit it; the bridge owns output and
        # compilation.
        cmd = ["codex", "--dangerously-bypass-approvals-and-sandbox"]
        if self.base_url:
            codex_base_url = self.base_url.rstrip("/")
            if not re.search(r"/v1$", codex_base_url):
                codex_base_url += "/v1"
            cmd.extend([
                "-c", "model_provider=bulbasaur",
                "-c", "model_providers.bulbasaur.name=bulbasaur",
                "-c", f"model_providers.bulbasaur.base_url={codex_base_url}",
                "-c", "model_providers.bulbasaur.env_key=OPENAI_API_KEY",
                "-c", "model_providers.bulbasaur.wire_api=responses",
            ])
        cmd.extend([
            "exec", "--ephemeral",
            "--skip-git-repo-check",
            "--cd", self.base_source_path, "--output-last-message", str(result_file),
        ])
        if self.model:
            cmd.extend(["--model", self.model])
        cmd.append("-")
        return cmd


    def _seed_command(
        self,
        prompt: str,
        result_file: Path,
        source_root: str,
        workspace_dir: str,
        skill_path: Path,
    ) -> list[str]:
        """Build a seed-enrichment command with a writable workspace only."""
        if self.agent == "claude":
            cmd = [
                "claude", "--print", "--output-format", "text",
                "--no-session-persistence", "--dangerously-skip-permissions",
                "--add-dir", workspace_dir, "--add-dir", source_root,
                "--append-system-prompt", skill_path.read_text(encoding="utf-8"),
            ]
            if self.model:
                cmd.extend(["--model", self.model])
            cmd.append(prompt)
            return cmd

        # Seed enrichment uses the same intentionally unsandboxed Codex mode;
        # its writable scope is the retained seed-enrichment workspace and its
        # source input is a disposable snapshot.
        cmd = ["codex", "--dangerously-bypass-approvals-and-sandbox"]
        if self.base_url:
            codex_base_url = self.base_url.rstrip("/")
            if not re.search(r"/v1$", codex_base_url):
                codex_base_url += "/v1"
            cmd.extend([
                "-c", "model_provider=bulbasaur",
                "-c", "model_providers.bulbasaur.name=bulbasaur",
                "-c", f"model_providers.bulbasaur.base_url={codex_base_url}",
                "-c", "model_providers.bulbasaur.env_key=OPENAI_API_KEY",
                "-c", "model_providers.bulbasaur.wire_api=responses",
            ])
        cmd.extend([
            "exec", "--ephemeral",
            "--skip-git-repo-check", "--cd", workspace_dir,
            "--add-dir", source_root, "--output-last-message", str(result_file),
        ])
        if self.model:
            cmd.extend(["--model", self.model])
        cmd.append("-")
        return cmd

    def _run_mini(self, prompt: str, branch_id: int, log_dir: Optional[str], task_type: str, started: float) -> Optional[str]:
        trajectory = None
        if log_dir:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            trajectory = str(Path(log_dir) / f"branch_{branch_id}_{task_type}_trajectory.json")
        from mini_harness import run_mini_agent
        result = run_mini_agent(
            prompt,
            source_root=self.base_source_path,
            model=self.model,
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self.timeout,
            trajectory_path=trajectory,
        )
        output = result.get("submission", "") if isinstance(result, dict) else ""
        if log_dir:
            stamp = time.strftime("%Y%m%d_%H%M%S")
            Path(log_dir, f"branch_{branch_id}_{task_type}_{stamp}.json").write_text(
                json.dumps({
                    "agent": "mini",
                    "prompt": prompt,
                    "result": output,
                    "exit_status": result.get("exit_status") if isinstance(result, dict) else None,
                    "elapsed_seconds": round(time.time() - started, 3),
                }, indent=2),
                encoding="utf-8",
            )
        return _extract_result(output, branch_id)

    def run(self, prompt: str, branch_id: int, log_dir: Optional[str] = None, task_type: str = "generate") -> Optional[str]:
        started = time.time()
        if self.agent == "mini":
            result = self._run_mini(prompt, branch_id, log_dir, task_type, started)
            return result
        with tempfile.TemporaryDirectory(prefix="bulbasaur-agent-") as tmp:
            result_file = Path(tmp) / "last_message.txt"
            command = self._command(prompt, result_file)
            env = os.environ.copy()
            if self.api_key:
                env["BULBASAUR_AGENT_API_KEY"] = self.api_key
                if self.agent == "claude":
                    env["ANTHROPIC_API_KEY"] = self.api_key
                else:
                    env["OPENAI_API_KEY"] = self.api_key
            if self.base_url and self.agent == "claude":
                env["ANTHROPIC_BASE_URL"] = self.base_url
            # Both external CLIs bypass interactive permission prompts. The
            # source/workspace paths are supplied explicitly; callers should
            # place the run in a trusted workspace or outer container.
            try:
                proc = subprocess.run(
                    command,
                    input=prompt if self.agent == "codex" else None,
                    text=True,
                    capture_output=True,
                    cwd=self.base_source_path,
                    env=env,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"{self.agent} timed out after {self.timeout}s") from exc
            output = result_file.read_text(encoding="utf-8", errors="replace") if result_file.exists() else proc.stdout
            if proc.returncode != 0:
                raise RuntimeError(
                    f"{self.agent} exited with status {proc.returncode}: "
                    f"{proc.stderr[-4000:]}"
                )
            if log_dir:
                Path(log_dir).mkdir(parents=True, exist_ok=True)
                stamp = time.strftime("%Y%m%d_%H%M%S")
                log_path = Path(log_dir) / f"branch_{branch_id}_{task_type}_{stamp}.json"
                log_path.write_text(json.dumps({
                    "agent": self.agent,
                    "command": [shlex.quote(x) for x in command if x != prompt],
                    "prompt": prompt,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                    "returncode": proc.returncode,
                    "elapsed_seconds": round(time.time() - started, 3),
                    "result": output,
                }, indent=2), encoding="utf-8")
        return _extract_result(output, branch_id)


    def run_seed_task(
        self,
        prompt: str,
        *,
        source_root: str,
        workspace_dir: str,
        skill_path: str,
        trajectory_path: Optional[str] = None,
    ) -> dict:
        """Run the selected backend for corpus enrichment.

        Unlike mutator generation, seed enrichment needs a writable workspace so
        the agent can create generator scripts and candidate files. The caller
        supplies a disposable source snapshot for external CLIs; mini mounts the
        real source tree read-only through its own environment adapter.
        """
        started = time.time()
        workspace = Path(workspace_dir).resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        source = Path(source_root).resolve()
        skill = Path(skill_path).resolve()
        if self.agent == "mini":
            from mini_harness import run_mini_agent
            result = run_mini_agent(
                prompt,
                source_root=str(source),
                model=self.model,
                api_key=self.api_key,
                base_url=self.base_url,
                timeout=self.timeout,
                writable_dir=str(workspace),
                trajectory_path=trajectory_path,
                seed_mode=True,
            )
            return result

        with tempfile.TemporaryDirectory(prefix="bulbasaur-seed-agent-") as tmp:
            result_file = Path(tmp) / "last_message.txt"
            command = self._seed_command(
                prompt, result_file, str(source), str(workspace), skill
            )
            env = os.environ.copy()
            if self.api_key:
                env["BULBASAUR_AGENT_API_KEY"] = self.api_key
                if self.agent == "claude":
                    env["ANTHROPIC_API_KEY"] = self.api_key
                else:
                    env["OPENAI_API_KEY"] = self.api_key
            if self.base_url and self.agent == "claude":
                env["ANTHROPIC_BASE_URL"] = self.base_url
            try:
                proc = subprocess.run(
                    command,
                    input=prompt if self.agent == "codex" else None,
                    text=True,
                    capture_output=True,
                    cwd=str(workspace),
                    env=env,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"{self.agent} timed out after {self.timeout}s") from exc
            output = result_file.read_text(encoding="utf-8", errors="replace") if result_file.exists() else proc.stdout
            result = {
                "agent": self.agent,
                "submission": output,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "returncode": proc.returncode,
                "exit_status": "Submitted" if proc.returncode == 0 else f"Exit {proc.returncode}",
                "elapsed_seconds": round(time.time() - started, 3),
            }
            if trajectory_path:
                log_path = Path(trajectory_path)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_text(json.dumps({
                    **result,
                    "command": [shlex.quote(x) for x in command if x != prompt],
                    "prompt": prompt,
                    "source_root": str(source),
                    "workspace_dir": str(workspace),
                }, indent=2), encoding="utf-8")
            if proc.returncode != 0:
                raise RuntimeError(
                    f"{self.agent} seed enrichment exited with status {proc.returncode}: "
                    f"{proc.stderr[-4000:]}"
                )
            return result


class LLMAgent(AgentCLI):
    """Agent-backed request facade used by the bridge."""

    def __init__(self, base_source_path=None, agent=None, model=None,
                 timeout=None, skill_path=None):
        super().__init__(base_source_path, agent, model, timeout, skill_path)
        self._last_request = None

    def _remember(self, values: tuple):
        self._last_request = values

    def _make_prompt(self, values, **kwargs):
        self._remember(values)
        return self._prompt(*values, **kwargs)

    def generate_mutation_function(self, branch_id, edge_id, branch_location,
                                   branch_context, branch_start_line, branch_end_line,
                                   edge_location, edge_context, edge_start_line,
                                   edge_end_line, branch_function_name=None,
                                   log_dir=None):
        values = (branch_id, edge_id, branch_location, branch_context,
                  branch_start_line, branch_end_line, edge_location, edge_context,
                  edge_start_line, edge_end_line)
        prompt = self._make_prompt(values, branch_function_name=branch_function_name)
        return self.run(prompt, branch_id, log_dir, "generate")

    def regenerate_mutation_function(self, branch_id, edge_id, branch_location,
                                     branch_context, branch_start_line, branch_end_line,
                                     edge_location, edge_context, edge_start_line,
                                     edge_end_line, previous_rust_code,
                                     branch_function_name=None, log_dir=None):
        values = (branch_id, edge_id, branch_location, branch_context,
                  branch_start_line, branch_end_line, edge_location, edge_context,
                  edge_start_line, edge_end_line)
        prompt = self._make_prompt(values, branch_function_name=branch_function_name,
                                   previous_code=previous_rust_code)
        return self.run(prompt, branch_id, log_dir, "regenerate")

    def fix_compilation_error(self, branch_id, rust_code, error_message, log_dir=None):
        if not self._last_request:
            raise RuntimeError("cannot fix compilation without the original branch request")
        prompt = self._make_prompt(self._last_request, previous_code=rust_code,
                                   compile_error=error_message)
        return self.run(prompt, branch_id, log_dir, "fix_compile")
