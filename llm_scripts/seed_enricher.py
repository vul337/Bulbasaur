#!/usr/bin/env python3
"""Agent-assisted initial corpus enrichment for Bulbasaur.

The agent receives a source snapshot and corpus summary plus a separate writable
workspace. External CLI snapshots are made read-only; the agent may write
generator scripts and complex seed files in the workspace, and this module
copies the agent-produced files into a new corpus directory after lightweight
safety and duplicate checks.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Optional

from agent_cli import AgentCLI


SEED_SKILL = Path(__file__).with_name("skills") / "bulbasaur-seed-enrichment" / "SKILL.md"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _copy_originals(source: Path, destination: Path) -> tuple[int, set[str]]:
    count = 0
    hashes: set[str] = set()
    for path in sorted(source.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        hashes.add(_sha256(path))
        count += 1
    return count, hashes


def _safe_suffix(path: Path) -> str:
    suffix = path.suffix.lower()
    return suffix if re.fullmatch(r"\.[a-z0-9._-]{1,16}", suffix or "") else ".seed"



def _copy_source_snapshot(source: Path, destination: Path) -> None:
    """Copy regular source files while dropping links and build artifacts.

    External CLIs need a writable additional directory for their workspace.
    They therefore receive this disposable snapshot instead of the operator's
    source tree, so an accidental edit cannot alter the target.
    """
    excluded_dirs = {".git", "target", "bin", "build", "CMakeFiles", "cmake-build-debug",
                     "cmake-build-release", "node_modules", ".venv", "__pycache__",
                     "obj", "out", "dist", ".cache", "coverage"}
    destination.mkdir(parents=True, exist_ok=True)
    for current, dirs, files in os.walk(source, followlinks=False):
        current_path = Path(current)
        dirs[:] = [
            name for name in dirs
            if name not in excluded_dirs and not (current_path / name).is_symlink()
        ]
        relative = current_path.relative_to(source)
        target_dir = destination / relative
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in files:
            source_file = current_path / name
            if source_file.is_symlink() or not source_file.is_file():
                continue
            target_file = target_dir / name
            shutil.copy2(source_file, target_file)
            try:
                os.chmod(target_file, 0o444)
            except OSError:
                pass


def enrich_corpus(
    *,
    input_corpus: str,
    output_corpus: str,
    source_root: str,
    agent: str = "mini",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    agent_timeout: int = 900,
    conversation_dir: Optional[str] = None,
    workspace_dir: Optional[str] = None,
) -> dict:
    """Copy the original corpus and add agent-produced candidates."""
    source = Path(input_corpus).resolve()
    destination = Path(output_corpus).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"corpus directory not found: {source}")
    if destination == source or source in destination.parents:
        raise ValueError("enriched corpus must be outside the input corpus directory")
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite existing enriched corpus: {destination}")
    destination.mkdir(parents=True)
    original_count, known_hashes = _copy_originals(source, destination)

    if workspace_dir:
        work = Path(workspace_dir).resolve()
        if work == source or source in work.parents:
            raise ValueError("seed workspace must be outside the input corpus")
        if work == destination or work in destination.parents:
            raise ValueError("seed workspace must not contain the enriched corpus")
    else:
        work = destination.parent / f"{destination.name}.seed_work"
    if work.exists():
        work = work.parent / f"{work.name}.{int(time.time())}"
    work.mkdir(parents=True)
    candidates = work / "candidates"
    scripts = work / "scripts"
    candidates.mkdir()
    scripts.mkdir()
    source_summary = []
    for path in sorted(source.rglob("*")):
        if path.is_file() and not path.is_symlink():
            source_summary.append(f"{path.relative_to(source)} ({path.stat().st_size} bytes)")
            if len(source_summary) >= 40:
                break
    selected_agent = (agent or os.getenv("BULBASAUR_AGENT", "mini")).lower()
    if selected_agent not in {"mini", "codex", "claude"}:
        raise ValueError(f"unsupported seed agent: {selected_agent}")
    source_for_agent = Path(source_root).resolve()
    snapshot_context = None
    if selected_agent != "mini":
        snapshot_context = tempfile.TemporaryDirectory(prefix="bulbasaur-seed-source-")
        snapshot_root = Path(snapshot_context.name) / "source"
        try:
            _copy_source_snapshot(source_for_agent, snapshot_root)
        except Exception:
            snapshot_context.cleanup()
            raise
        source_for_agent = snapshot_root

    task = f"""{SEED_SKILL.read_text(encoding='utf-8')}

Enrich the initial corpus for this fuzzing target.

Source tree (read-only): {source_for_agent}
The source tree and the corpus summary in this prompt are the only target-specific
inputs. Decide how many candidates are justified by the
format and parser complexity. Generate a small set for simple formats and more
distinct structural variants for complex formats; do not pad the corpus to meet
a fixed count and stop when additional files would be redundant. Prefer parser
boundary and structural diversity over copying many redundant fixtures. The writable
workspace is the actual current working directory. Put repeatable generators in $PWD/scripts and final
files in $PWD/candidates; do not assume /workspace exists. The host retains this
workspace under the fuzz output directory. You may inspect the source and corpus
summary, but do not modify the source tree.

Existing corpus sample (original files remain outside your writable workspace):
{chr(10).join(source_summary) or '<empty corpus>'}

When all useful candidates are saved, print the completion sentinel as the first
line and then a concise summary. The files, not the summary, are the deliverable.
"""
    # Keep the writable workspace under the fuzz output directory; the trajectory
    # is stored alongside it under output/conversation_logs for one audit bundle.
    trajectory = work / "agent_trajectory.json"
    if conversation_dir:
        conversation_root = Path(conversation_dir).resolve()
        conversation_root.mkdir(parents=True, exist_ok=True)
        trajectory = conversation_root / f"seed_enrichment_{int(time.time())}_trajectory.json"
    started = time.monotonic()
    try:
        runner = AgentCLI(
            base_source_path=str(Path(source_root).resolve()),
            agent=selected_agent,
            model=model,
            timeout=agent_timeout,
        )
        agent_result = runner.run_seed_task(
            task,
            source_root=str(source_for_agent),
            workspace_dir=str(work),
            skill_path=str(SEED_SKILL),
            trajectory_path=str(trajectory),
        )
    finally:
        if snapshot_context is not None:
            snapshot_context.cleanup()

    generated: list[dict] = []
    candidate_count = 0
    for candidate in sorted(candidates.rglob("*")):
        if not candidate.is_file() or candidate.is_symlink():
            continue
        candidate_count += 1
        size = candidate.stat().st_size
        if size > 4 * 1024 * 1024:
            continue
        digest = _sha256(candidate)
        if digest in known_hashes:
            continue
        output_name = f"agent_{digest[:16]}{_safe_suffix(candidate)}"
        output_path = destination / output_name
        shutil.copy2(candidate, output_path)
        known_hashes.add(digest)
        generated.append({
            "source": str(candidate.relative_to(work)),
            "size": size,
            "sha256": digest,
            "output": str(output_path),
            "selection": "agent_generated",
        })
    report = {
        "input_corpus": str(source),
        "output_corpus": str(destination),
        "source_root": str(Path(source_root).resolve()),
        "agent_backend": selected_agent,
        "original_count": original_count,
        "candidate_count": candidate_count,
        "generated_count": len(generated),
        "generated": generated,
        "agent": {
            "exit_status": agent_result.get("exit_status") if isinstance(agent_result, dict) else None,
            "submission": agent_result.get("submission", "") if isinstance(agent_result, dict) else "",
            "elapsed_seconds": round(time.monotonic() - started, 3),
        },
        "workdir": str(work),
        "trajectory_path": str(trajectory),
    }
    # Keep metadata out of the AFL corpus: every regular file in that directory
    # is a possible fuzzing input. The retained work directory is the inspection
    # and reproducibility bundle instead.
    report["report_path"] = str(work / "seed_enrichment_report.json")
    (work / "seed_enrichment_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
