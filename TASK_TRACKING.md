# Task Tracking

Last update: 2026-02-08

## Working Rules
- Before starting a task, read this file and move the task to `In Progress`.
- After finishing a task, move it to `Done` with evidence (files/tests).
- Keep tests updated with TDD mindset for code-impacting changes.
- Prefer smallest safe change set, then verify with tests.

## SemVer / Versioning Notes
- Current released version: `5.4.8`.
- Keep `5.4.8` for documentation-only and test-only cleanup commits.
- Bump to `5.4.9` only when a runtime behavior or public contract changes.
- If version is bumped, update in lockstep:
  - `src/__version__.py`
  - `Dockerfile` (`LABEL version`)
  - `README.md` version badge
  - `CHANGELOG.md`
  - tag/release metadata

## Backlog
- [ ] None.

## In Progress
- [ ] None.

## Done
- [x] Release `v5.4.8` validated and published (git tag, GitHub release, Docker images).
- [x] Global non-e2e test suite green: `1242 passed, 44 skipped`.
- [x] Create guard tests for version metadata consistency (`__version__`, Docker label, README badge).
- [x] Align README version badge with current release (`5.4.8`).
- [x] Update architecture documentation header/status to current release (`5.4.8`) with explicit historical note.
- [x] Re-run targeted tests for metadata guards (`3 passed`).
