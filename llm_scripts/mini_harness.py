#!/usr/bin/env python3
"""Project-local mini-swe-agent harness.

The upstream package is vendored under ``third_party/mini-swe-agent``.  This
adapter deliberately exposes only the small interface Bulbasaur needs:
the agent can inspect a source tree and execute shell commands in a bubblewrap
sandbox.  Mutator runs are read-only; corpus enrichment runs additionally get
one explicitly bound writable workspace where scripts and candidate files may
be created.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MINI_SRC = PROJECT_ROOT / "third_party" / "mini-swe-agent" / "src"
SUBMISSION_SENTINEL = "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"
logger = logging.getLogger("bulbasaur.mini_harness")


def _load_mini():
    """Import the vendored package lazily so Claude/Codex users need no deps."""
    source = str(MINI_SRC)
    if source not in sys.path:
        sys.path.insert(0, source)
    # LiteLLM otherwise tries to download its model-cost registry during
    # import.  FuzzBench runners are often intentionally offline until the
    # configured gateway is called; the bundled registry is enough for model
    # dispatch and avoids delaying fuzzer startup on an unrelated download.
    os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
    # Custom OpenAI-compatible gateways (for example Luna/Terra endpoints)
    # are not necessarily present in LiteLLM's registry.  Agent execution
    # should not fail after a successful response merely because cost metadata
    # is unavailable.
    os.environ.setdefault("MSWEA_COST_TRACKING", "ignore_errors")
    # The upstream package prints a migration banner on import. The bridge is
    # a long-running fuzzer helper, so keep that banner out of its protocol/log
    # stream unless a caller explicitly asks for it.
    os.environ.setdefault("MSWEA_SILENT_STARTUP", "1")
    try:
        import minisweagent  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "mini-swe-agent dependencies are missing; install "
            "llm_scripts/requirements.txt"
        ) from exc

    # Some FuzzBench runner images currently ship a LiteLLM/OpenAI/Pydantic
    # combination where this forward-referenced OpenAI Responses type is not
    # imported into litellm.types.utils.  The failure appears only when the
    # first completion constructs a response model, after the agent probe has
    # already succeeded. Import and rebuild it once so OpenAI-compatible gateways
    # use the same vendored harness path.
    try:
        import litellm.types.utils as litellm_utils
        from litellm.types.llms.openai import ChatCompletionReasoningSummaryTextBlock

        if not hasattr(litellm_utils, "ChatCompletionReasoningSummaryTextBlock"):
            litellm_utils.ChatCompletionReasoningSummaryTextBlock = ChatCompletionReasoningSummaryTextBlock
        litellm_utils.Message.model_rebuild(force=True)
    except (ImportError, AttributeError, TypeError):
        # Older LiteLLM releases do not need this compatibility shim.
        pass


def mini_available() -> bool:
    """Return whether the vendored harness and its runtime dependencies import."""
    try:
        _load_mini()
        from minisweagent.agents.default import DefaultAgent  # noqa: F401
        from minisweagent.models.litellm_model import LitellmModel  # noqa: F401
        if os.getenv("BULBASAUR_MINI_ALLOW_UNSANDBOXED", "0") == "1":
            # FuzzBench's outer container (or an operator-managed host) can
            # be the isolation boundary.  In this explicit mode mini does not
            # need bubblewrap at all and will execute commands directly,
            # avoiding a nested user namespace entirely.
            return True
        executable = shutil.which(os.getenv("MSWEA_BUBBLEWRAP_EXECUTABLE", "bwrap"))
        if executable is None:
            return False
        probe = subprocess.run(
            [
                executable, "--die-with-parent", "--unshare-user-try", "--unshare-net",
                "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin",
                "--proc", "/proc", "--dev", "/dev", "/usr/bin/true",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return probe.returncode == 0
    except (ImportError, RuntimeError):
        return False


def _normalise_base_url(base_url: Optional[str]) -> Optional[str]:
    if not base_url:
        return None
    value = base_url.rstrip("/")
    if value.endswith("/v1"):
        return value
    return value + "/v1"


def _redact_trajectory(path: Optional[str]) -> None:
    """Remove gateway credentials from mini-swe-agent's saved trajectory."""
    if not path:
        return
    target = Path(path)
    if not target.is_file():
        return
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return

    def redact(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: "<redacted>" if key.lower() in {"api_key", "authorization"}
                else redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    target.write_text(json.dumps(redact(document), ensure_ascii=False, indent=2), encoding="utf-8")


def _model_name(model: Optional[str], base_url: Optional[str]) -> str:
    value = model or os.getenv("BULBASAUR_AGENT_MODEL") or "gpt-5.6-luna"
    if "/" not in value and base_url:
        return "openai/" + value
    return value


def _path_ancestors(path: Path) -> list[Path]:
    """Return missing mountpoint directories from / down to path.parent."""
    path = path.resolve()
    parent = path if path.is_dir() else path.parent
    ancestors: list[Path] = []
    while str(parent) not in {"", "/"}:
        ancestors.append(parent)
        parent = parent.parent
    return list(reversed(ancestors))


class BulbasaurEnvironment:
    """A minimal mini-swe-agent Environment with an explicit filesystem policy."""

    def __init__(
        self,
        *,
        source_root: str,
        writable_dir: Optional[str] = None,
        readonly_roots: Iterable[str] = (),
        timeout: int = 60,
        max_output_chars: int = 24000,
    ):
        self.source_root = Path(source_root).resolve()
        if not self.source_root.is_dir():
            raise FileNotFoundError(f"source root is not a directory: {source_root}")
        self.writable_dir = Path(writable_dir).resolve() if writable_dir else None
        if self.writable_dir:
            self.writable_dir.mkdir(parents=True, exist_ok=True)
        roots = [self.source_root, *(Path(p).resolve() for p in readonly_roots)]
        # A single read-only bind of a parent also exposes all requested
        # descendants. Avoid nested bind mounts, which bubblewrap rejects on
        # some kernels and which add no access beyond the parent bind.
        reduced: list[Path] = []
        for root in sorted({p for p in roots if p.exists()}, key=lambda p: (len(p.parts), str(p))):
            if any(root == parent or parent in root.parents for parent in reduced):
                continue
            reduced.append(root)
        self.readonly_roots = reduced
        self.timeout = max(1, int(timeout))
        self.max_output_chars = max(1000, int(max_output_chars))
        self.config = type(
            "BulbasaurEnvironmentConfig",
            (),
            {
                "cwd": str(self.writable_dir or self.source_root),
                "timeout": self.timeout,
                "env": {"PAGER": "cat", "MANPAGER": "cat", "LESS": "-R"},
            },
        )()

    def _wrapper(self, cwd: Path) -> list[str]:
        executable = os.getenv("MSWEA_BUBBLEWRAP_EXECUTABLE", "bwrap")
        if shutil.which(executable) is None:
            raise RuntimeError(
                "mini harness requires bubblewrap (bwrap); install it or use --agent codex/claude"
            )
        args = [
            executable,
            "--die-with-parent",
            "--unshare-user-try",
            "--unshare-net",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc", "/etc",
            "--tmpfs", "/tmp",
            "--proc", "/proc",
            "--dev", "/dev",
            "--new-session",
            "--setenv", "PATH", "/usr/local/bin:/usr/sbin:/usr/bin:/bin",
            "--setenv", "HOME", "/tmp/home",
        ]
        # Keep network isolation as the secure default. Containerized hosts
        # that reject RTM_NEWADDR may explicitly opt into unsandboxed execution for
        # local testing; no API credentials are passed to the sandbox env.
        if os.getenv("BULBASAUR_MINI_ALLOW_NETWORK", "0") == "1":
            args.remove("--unshare-net")
        for optional in ("/usr/local", "/sbin", "/lib32", "/libx32"):
            if Path(optional).exists():
                args.extend(["--ro-bind", optional, optional])
        args.extend(["--dir", "/tmp/home"])

        # Bind only the exact source/target directories. Ancestors are empty
        # mountpoint directories, so unrelated host files remain invisible.
        created: set[str] = set()
        for root in self.readonly_roots:
            for ancestor in _path_ancestors(root):
                key = str(ancestor)
                if key not in created:
                    args.extend(["--dir", key])
                    created.add(key)
            args.extend(["--ro-bind", str(root), str(root)])

        if self.writable_dir:
            args.extend(["--dir", "/workspace", "--bind", str(self.writable_dir), "/workspace"])
            sandbox_cwd = "/workspace"
        else:
            sandbox_cwd = str(cwd)
        args.extend(["--chdir", sandbox_cwd])
        return args

    def execute(self, action: dict, cwd: str = "", *, timeout: int | None = None) -> dict[str, Any]:
        command = action.get("command", "")
        if not isinstance(command, str) or not command.strip():
            return {"output": "", "returncode": -1, "exception_info": "empty command"}
        host_cwd = Path(cwd).resolve() if cwd else (self.writable_dir or self.source_root)
        if not host_cwd.is_dir():
            host_cwd = self.writable_dir or self.source_root
        unsandboxed = os.getenv("BULBASAUR_MINI_ALLOW_UNSANDBOXED", "0") == "1"
        cmd = ["bash", "-c", command] if unsandboxed else self._wrapper(host_cwd) + ["bash", "-c", command]
        deadline = timeout or self.timeout
        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env={"PATH": "/usr/local/bin:/usr/sbin:/usr/bin:/bin", "HOME": "/tmp/home", "LC_ALL": "C"},
                cwd=str(host_cwd) if unsandboxed else None,
                start_new_session=True,
            )
            try:
                stdout, _ = proc.communicate(timeout=deadline)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                stdout, _ = proc.communicate()
                output = stdout[-self.max_output_chars :]
                result = {
                    "output": output,
                    "returncode": -1,
                    "exception_info": f"command timed out after {deadline}s",
                    "extra": {"exception_type": "TimeoutExpired"},
                }
                return result
            output = stdout or ""
            if len(output) > self.max_output_chars:
                output = output[: self.max_output_chars // 2] + "\n...[output truncated]...\n" + output[-self.max_output_chars // 2 :]
            result = {"output": output, "returncode": proc.returncode, "exception_info": ""}
        except Exception as exc:
            result = {
                "output": "",
                "returncode": -1,
                "exception_info": f"sandbox command failed: {exc}",
                "extra": {"exception_type": type(exc).__name__},
            }
        self._check_finished(result)
        result.setdefault("extra", {})["elapsed_seconds"] = round(time.monotonic() - started, 3)
        return result

    @staticmethod
    def _check_finished(output: dict[str, Any]) -> None:
        from minisweagent.exceptions import Submitted

        lines = output.get("output", "").lstrip().splitlines(keepends=True)
        if lines and lines[0].strip() == SUBMISSION_SENTINEL and output.get("returncode") == 0:
            submission = "".join(lines[1:])
            raise Submitted({
                "role": "exit",
                "content": submission,
                "extra": {"exit_status": "Submitted", "submission": submission},
            })

    def get_template_vars(self, **kwargs) -> dict[str, Any]:
        return {
            "cwd": "/workspace" if self.writable_dir else str(self.source_root),
            "source_root": str(self.source_root),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            **kwargs,
        }

    def serialize(self) -> dict:
        return {
            "info": {
                "environment_type": f"{self.__class__.__module__}.{self.__class__.__name__}",
                "source_root": str(self.source_root),
                "writable_dir": str(self.writable_dir) if self.writable_dir else None,
                "readonly_roots": [str(p) for p in self.readonly_roots],
            }
        }


MUTATOR_SYSTEM = """You are the Bulbasaur mutator agent. You have one bash tool.
Use exactly one bash command per response. Read/search the source and reason about
the requested branch, but never edit source, build the target, use wllvm, or use a
callgraph tool. The only callable tool is bash; never call mutate_branch_* or any
other tool. Put the complete requested Rust function in a temporary
file and use one final command that prints the protocol sentinel first and then
that file, for example: `printf '%s\\n' COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT;
cat /tmp/mutator.rs`. The sentinel must be the first output line and the Rust
function must follow it.


Treat the supplied source window as a starting point. If the branch is not a
trivial input-local comparison, do source inspection before writing the mutator:
read the enclosing function, follow the relevant helper definition and one caller
or callee, and inspect relevant headers/constants/structures plus the fuzz harness
or input-file parsing. For a complex path, make at least five separate focused bash turns and no more
than ten before the final submission command; the final command does not count. Do
not spend turns on broad repository scans. A direct comparison may be handled in one
turn when its byte layout is unambiguous. Do not create
`/tmp/mutator.rs` or submit the final sentinel until the source evidence supports
the input offset, length, encoding, endianness, and bounds.
"""

SEED_SYSTEM = """You are the Bulbasaur corpus-seed agent. You have one bash tool.
Inspect the target source and the supplied corpus summary, then create useful binary or
text inputs under $PWD/candidates. You may write generator scripts under
$PWD/scripts and inspect the supplied source tree and corpus summary. No target
executable is provided in this seed stage. The current
working directory is the writable workspace retained under the fuzz output
directory (the normal sandbox maps it to /workspace); use $PWD and do not
write outside this workspace. Do not modify the source tree. Decide how many candidates are justified by the format and parser
complexity: keep simple formats small, add more structural variants for complex
formats, and do not pad to a fixed count. Preserve every useful candidate as a
file; the host will copy those files into the corpus after duplicate and
safety checks. When finished, use one final command that prints
COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT as its first line followed by a short
summary. The sentinel must be the first output line.
"""


def run_mini_agent(
    task: str,
    *,
    source_root: str,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    timeout: int = 900,
    writable_dir: Optional[str] = None,
    readonly_roots: Iterable[str] = (),
    trajectory_path: Optional[str] = None,
    seed_mode: bool = False,
) -> dict[str, Any]:
    """Run one agent task and return mini-swe-agent's exit metadata."""
    _load_mini()
    from minisweagent.agents.default import DefaultAgent
    from minisweagent.models.litellm_model import LitellmModel
    from minisweagent.models.litellm_response_model import LitellmResponseModel

    endpoint = _normalise_base_url(base_url or os.getenv("BULBASAUR_AGENT_BASE_URL"))
    if not endpoint:
        raise RuntimeError(
            "mini agent requires BULBASAUR_AGENT_BASE_URL; configure the Luna gateway"
        )
    api_key = api_key or os.getenv("BULBASAUR_AGENT_API_KEY") or os.getenv("OPENAI_API_KEY")
    selected_model = _model_name(model, endpoint)
    model_kwargs: dict[str, Any] = {"drop_params": True}
    # LiteLLM's default retry policy can keep an unavailable local model
    # request alive for several minutes. Bound each API call and make the
    # retry count explicit; operators can raise either value for a slower
    # model through environment variables.
    try:
        api_timeout = int(os.getenv("BULBASAUR_MINI_API_TIMEOUT", "120"))
    except ValueError:
        api_timeout = 120
    model_kwargs["timeout"] = max(1, min(int(timeout), api_timeout))
    if endpoint:
        model_kwargs["api_base"] = endpoint
    if api_key:
        model_kwargs["api_key"] = api_key
    use_chat = selected_model.startswith("anthropic/") or os.getenv("BULBASAUR_MINI_CHAT_API") == "1"
    model_impl = LitellmModel if use_chat else LitellmResponseModel
    llm = model_impl(
        model_name=selected_model,
        model_kwargs=model_kwargs,
        cost_tracking="ignore_errors",
    )
    environment = BulbasaurEnvironment(
        source_root=source_root,
        writable_dir=writable_dir,
        readonly_roots=readonly_roots,
        timeout=min(max(1, int(timeout)), 120),
    )
    system = SEED_SYSTEM if seed_mode else MUTATOR_SYSTEM
    instance = """Work on this Bulbasaur task.\n\n{{ task }}\n\nUse the available bash tool and finish with the required sentinel."""
    agent = DefaultAgent(
        llm,
        environment,
        system_template=system,
        instance_template=instance,
        step_limit=0,
        cost_limit=0.0,
        wall_time_limit_seconds=int(timeout),
        max_consecutive_format_errors=3,
        output_path=Path(trajectory_path) if trajectory_path else None,
    )
    previous_retry_limit = os.environ.get("MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT")
    os.environ["MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT"] = os.getenv(
        "BULBASAUR_MINI_RETRY_ATTEMPTS", "2"
    )
    try:
        return agent.run(task)
    finally:
        _redact_trajectory(trajectory_path)
        if previous_retry_limit is None:
            os.environ.pop("MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT", None)
        else:
            os.environ["MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT"] = previous_retry_limit
        # The workspace is intentionally owned by the caller and retained for
        # inspection; only mini-swe-agent's private state is cleaned by Python.
        pass
