# Vendored mini-swe-agent

This directory vendors [SWE-agent/mini-swe-agent](https://github.com/SWE-agent/mini-swe-agent)
for use as Bulbasaur's optional in-project agent harness.

- Upstream commit: `25941c8`
- Upstream license: MIT (see `LICENSE.md`)
- The Bulbasaur adapter lives in `llm_scripts/mini_harness.py` and imports the
  package directly from `src/`; users do not need to install the upstream CLI.

Keep this file and `LICENSE.md` when updating the vendored source so the origin
and license remain visible in source distributions.
