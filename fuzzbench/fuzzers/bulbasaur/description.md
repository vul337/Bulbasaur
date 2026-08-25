# Bulbasaur

Bulbasaur is an agent-assisted, branch-guided greybox fuzzer.  This
FuzzBench integration builds fast/full/trace/debug target variants and runs the
agent bridge with the lightweight project-local mini-swe-agent harness by
default (`BULBASAUR_FUZZBENCH_AGENT=mini`).  Claude Code and Codex can still be
selected through the normal Bulbasaur environment variables.

Repository: [https://github.com/vul337/Bulbasaur.git](https://github.com/vul337/Bulbasaur.git)

The legacy self-implemented agent has been replaced by a common bridge for Claude Code, Codex, and the vendored mini harness. `mini` is the default; Claude Code and Codex are recommended for the strongest results.

[builder.Dockerfile](builder.Dockerfile) ·
[runner.Dockerfile](runner.Dockerfile) ·
[fuzzer.py](fuzzer.py)
