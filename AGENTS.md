# Repository Guidelines

<!-- codex-shared-policy:start -->
## Codex Shared Policy (Managed)

Source of truth: `prompts/codex-shared-agents.md`

This file is the canonical shared policy for repo-level `AGENTS.md` files in
git-backed repositories under `/Users/marat/Developments/microservices`.

## Cache policy
- Use only repo-local `.cache` for temporary build and tool artifacts.
- Do not create or rely on repo-local `.gocache`.
- For Go commands, prefer these locations:
  - `XDG_CACHE_HOME=$PWD/.cache`
  - `GOCACHE=$PWD/.cache/go-build`
  - `GOMODCACHE=$PWD/.cache/gomod`
  - `GOBIN=$PWD/.cache/bin`
- Put disposable local binaries in `.cache/bin`.
- Treat `.cache` as disposable local state. Do not commit it.

## Workspace hygiene
- Do not introduce extra cache directories when `.cache` can be used instead.
- Keep temporary logs, generated reports, and ad-hoc tooling output under
  `.cache` when practical.
- Do not store persistent project data in `.cache`.
- If a repo has stricter local requirements, document them in that repo's
  `AGENTS.md` below the managed shared block.

## Scope
- This policy is synced into repo-level `AGENTS.md` files by
  `prompts/scripts/sync_agents.py`.
- The canonical source of truth is this file, not the generated copies.
<!-- codex-shared-policy:end -->

## Repository-Specific Notes
- Add repo-specific instructions here when needed.
