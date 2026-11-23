# CLAUDE.md

@AGENTS.md

## Claude Code notes
- Work directly on `feat/<slug>` / `fix/<slug>` branches and run the verification commands in `AGENTS.md` before pushing.
- Commit with a single-line Conventional Commit message (`git commit -m '<subject>'`) with no attribution trailers.
- Use subagents when parallelizing disjoint code modules or verification; never have two writers edit the same files concurrently.
