# Conductor Decision: CI Strategy for v5.0.0

**Reference**: `conductor/QUESTION_GITHUB_CI_TESTS.md`
**Date**: 2025-12-27
**Status**: DECIDED

---

## The Decision
**Selected Strategy: Option D (Hybrid) - Non-Blocking Infrastructure Tests**

Conductor advises to **keep the CI pipeline active but make "heavy" infrastructure tests (Docker/Helm) non-blocking**, while keeping "light" code quality tests (Unit/Lint) mandatory.

### Rationale
1.  **Deployment Reality**: The VPS deployment plan (`conductor/tracks/v5_0_0_vps_deployment/plan.md`) explicitly uses **Helm and Kubernetes (K3s/MicroK8s)**. Therefore, the `helm-test` job **IS relevant** and should not be permanently deleted.
2.  **Immediate Priority**: The goal is to ship `v5.0.0`. Blocking this release due to CI infrastructure timeouts or flakes (common with `kind` in GitHub Actions) is counter-productive.
3.  **Quality Baseline**: Unit tests and linting represent the minimum acceptable quality bar and are fast/cheap. These must remain blocking.

---

## Detailed Policy

| Test Suite | Status | Reasoning |
| :--- | :--- | :--- |
| **Linting** (pre-commit) | **Blocking** 🔴 | Fast, enforces code style, prevents technical debt. |
| **Unit Tests** (pytest) | **Blocking** 🔴 | Fast, verifies core logic, prevents regression in logic. |
| **Docker Build** | **Non-Blocking** 🟡 | Slow. Failures here are often due to registry/network issues in CI. |
| **Helm/K8s Test** | **Non-Blocking** 🟡 | Very Slow/Flaky. Vital for long-term stability but shouldn't block v5.0.0 release if local testing works. |

---

## Answers to Specific Questions

1.  **Should we invest time fixing CI?**
    *   **No**, not for the `helm-test` / `docker-build` jobs right now. Prioritize the VPS deployment. If Unit tests fail, **Yes**, fix them.

2.  **Deployment Model?**
    *   **Automated-capable Manual Deployment**. We use Helm (automated tool) but trigger it manually for now. We want the *option* for full GitOps later, so don't delete the CI jobs.

3.  **Solo vs Team?**
    *   **Treat as Team/Public**. The project structure implies high standards. Keep CI visible to welcome future contributors or bots.

---

## Next Steps (Action Plan)

1.  **Modify `.github/workflows/test.yml`**:
    *   Add `continue-on-error: true` to `docker-build` and `helm-test` jobs.
    *   Ensure `test` and `lint` jobs remain strict.
2.  **Proceed with VPS Deployment**:
    *   Rely on manual verification for the Docker/Helm stages during the deployment to the VPS.
3.  **Revisit Post-v5.0.0**:
    *   Create a "Tech Debt" track to fix the CI flakes properly later.

---

**Conductor Status**: decision logged. Awaiting implementation.
