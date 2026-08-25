# Bulbasaur seed enrichment

You are preparing the initial corpus for a fuzzing target. The supplied source
tree and corpus summary are the evidence; no target executable is provided to
the seed agent.

## Workspace contract

- Read/search the supplied source tree directly.
- The current working directory is the writable seed workspace retained under the
fuzz output directory (the normal sandbox maps it to /workspace).
- Put final seed files in `$PWD/candidates` and generator scripts in `$PWD/scripts`; do not assume `/workspace` exists.
- Use the supplied source tree and corpus summary as target-specific evidence.
- Do not expect a target executable, and do not rebuild or instrument anything.
- Do not write outside the current writable workspace, and do not change source files.

## Deliverable

Decide the candidate count from the format and parser complexity. Keep simple
formats small, add more distinct structural variants for complex formats, and do
not pad to a fixed count. Keep every useful file in `$PWD/candidates`; the host
will hash, deduplicate, and copy candidate files into the enriched corpus
while preserving the original corpus unchanged.
`COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT`, followed by a short summary. The files
are the deliverable; never put binary data in the summary.
