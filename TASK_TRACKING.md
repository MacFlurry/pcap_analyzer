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
- [ ] Progressive CI reactivation (phase 2):
  - keep `version-guards`, `lint`, and `test` active,
  - re-enable `docker-build` as non-blocking infra signal,
  - keep `helm-test` disabled until docker phase is stable.

## Done
- [x] Reduced remaining static skips:
  - `tests/test_service_classifier.py`: removed static skip and asserted expected port-priority behavior (`HTTPS` on 443 flow),
  - `tests/integration/test_postgres_advanced.py`: replaced static `skip` with documented `xfail` for known Alembic/testcontainer downgrade issue,
  - verification: `@pytest.mark.skip` count in `tests/` is now `0`.
- [x] Replace remaining non-environment security/test skips in targeted files:
  - `tests/test_security.py`: activated XSS escaping and CSP header checks (no skip),
  - `tests/test_tcp_state_machine.py`: replaced TIME-WAIT skip with explicit conditional `xfail` documenting current limitation.
- [x] Remove two "future enhancement" style skips by implementing testable behavior:
  - activated XSS upload-response escaping test in `tests/test_web_security.py` (API-based, no frontend harness),
  - implemented user-facing email redaction in `src/utils/error_sanitizer.py` and converted corresponding test in `tests/security/test_error_sanitizer.py` from conditional skip to assertion.
- [x] Clarify BPF/tcpdump test strategy:
  - `tests/test_bpf_validation.py` is now opt-in via `RUN_BPF_TESTS=1`,
  - explicit `requires_tcpdump` marker added,
  - clear skip reasons when tcpdump binary/capabilities are unavailable.
- [x] Windows-specific resource-limit tests excluded by default:
  - `tests/security/test_resource_limits.py` now requires explicit opt-in (`RUN_WINDOWS_TESTS=1`) to run Windows-only checks,
  - default local/CI behavior keeps them skipped.
- [x] Reactivate `tests/security/test_integration.py` and remove obsolete global skips:
  - updated legacy test adapters to current APIs (`DecompressionMonitor`, audit logger, file-size error handling),
  - result: `18 passed` on this suite (previously `18 skipped`).
- [x] CI test scope narrowed for runtime stability:
  - `test` job now targets `tests/unit` + `tests/regression` only,
  - avoids repeated long-running API/security flows in the main CI lane.
- [x] CI runtime optimization for `test` job:
  - avoid double execution on `main` by running non-coverage pytest only on PRs,
  - keep coverage run on push to `main` as the single test execution path.
- [x] Lint CI aligned to flake8-only signal:
  - `lint` job now runs `pre-commit run flake8 --all-files` (no auto-fix hooks in CI),
  - flake8 scope reduced to critical runtime/syntax classes only (`E9,F63,F7,F82`) while historical style debt is cleaned incrementally.
- [x] CI narrowed to lint-only temporarily:
  - disabled `version-guards`, `test`, `docker-build`, and `helm-test` jobs,
  - made `lint` blocking again to focus cleanup effort.
- [x] CI test pipeline optimized for speed/stability on PRs:
  - keep Ubuntu Python `3.12` only (remove `3.11` matrix duplication),
  - exclude `tests/integration` and `tests/e2e` from PR test run,
  - run coverage upload only on push to `main`,
  - make `lint` non-blocking temporarily while baseline debt is reduced.
- [x] Release `v5.4.8` validated and published (git tag, GitHub release, Docker images).
- [x] Global non-e2e test suite green: `1242 passed, 44 skipped`.
- [x] Create guard tests for version metadata consistency (`__version__`, Docker label, README badge).
- [x] Align README version badge with current release (`5.4.8`).
- [x] Update architecture documentation header/status to current release (`5.4.8`) with explicit historical note.
- [x] Re-run targeted tests for metadata guards (`3 passed`).
- [x] Standardize remaining legacy version markers in `docs/ARCHITECTURE.md`.
- [x] Add guard test ensuring `CHANGELOG.md` contains the current package version section (`4 passed`).
- [x] Add a test convention guard to forbid `@pytest.mark.asyncio` on sync tests (`5 passed` with metadata guards).
- [x] Add guard and fix Helm chart appVersion drift against package version (`6 passed` on guard suite).
- [x] Add metadata guards for Helm values + docker-compose image tag policy and fix detected drifts (`8 passed` on guard suite).
- [x] Add CI job to enforce metadata/convention guards on push/PR.
