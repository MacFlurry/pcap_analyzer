# Project Tracks

This file tracks all major tracks for the project. Each track has its own detailed plan in its respective folder.

---

## [ ] Track: Production VPS Deployment with HTTPS
*Context: Deploy to production VPS with Let's Encrypt automated TLS (pending infrastructure)*
*Link: [./conductor/tracks/vps_deployment_https/](./conductor/tracks/vps_deployment_https/)*

## [~] Track: Fix User Menu Not Showing After Password Change
*Context: Fix UX critical bug where user menu (profile + logout) doesn't appear after forced password change*
*Link: [./conductor/tracks/fix_password_change_ui_bug/](./conductor/tracks/fix_password_change_ui_bug/)*
*Priority: High | Type: Bug Fix | Status: Ready for Implementation*

## [x] Track: Version Synchronization & v5.0.0-rc2 Release
*Link: [./conductor/archive/tracks/version_sync_v5_0_0_rc2/](./conductor/archive/tracks/version_sync_v5_0_0_rc2/)*

## [x] Track: Password Reset Functionality
*Link: [./conductor/archive/tracks/password_reset/](./conductor/archive/tracks/password_reset/)*

## [x] Track: Let's Encrypt with cert-manager on Kubernetes
*Link: [./conductor/archive/tracks/letsencrypt_certmanager/](./conductor/archive/tracks/letsencrypt_certmanager/)*

## [x] Assistant Work: v4.28.2 & v4.28.3 - Documentation Email + Production Domain + Fix Dépendances 2FA
*Date: 2025-12-26*
*Report: [./conductor/ASSISTANT_REPORT_v4_28_2_v4_28_3.md](./conductor/ASSISTANT_REPORT_v4_28_2_v4_28_3.md)*

**v4.28.2:**
- ✅ Mise à jour `docs/EMAIL_SETUP.md` pour refléter configuration Proton Mail SMTP
- ✅ Changement domaine `pcap.local` → `pcaplab.com` dans Helm chart et ingress
- ✅ Documentation Kubernetes secrets et configuration Helm

**v4.28.3:**
- ⚠️ **Fix critique:** Ajout dépendances 2FA (`pyotp`, `qrcode`, `Pillow`) manquantes dans `pyproject.toml`
- ✅ Déployé et opérationnel en Kubernetes

**Recommandations:**
- Synchroniser `pyproject.toml` ↔ `requirements-web.txt` (seul pyproject.toml devrait être la source de vérité)
- Ajouter tests CI pour vérifier build Docker
- Tester envoi email en production

---

## [x] Track: Hardening Client-Side Authentication (Defense in Depth)
*Link: [./conductor/archive/tracks/client_side_auth_hardening/](./conductor/archive/tracks/client_side_auth_hardening/)*

## [x] Track: Vérification et Tests E2E v4.27.3
*Link: [./conductor/archive/tracks/v4_27_3_verification/](./conductor/archive/tracks/v4_27_3_verification/)*

## [x] Track: Documentation v5.0 (#28)
*Link: [./conductor/archive/v5_0_documentation/](./conductor/archive/v5_0_documentation/)*

## [x] Track: Audit de Sécurité v5.0 (#27)
*Link: [./conductor/archive/v5_0_security_audit/](./conductor/archive/v5_0_security_audit/)*

## [x] Track: Implémentation Authentification à deux facteurs (2FA) (#29)
*Link: [./conductor/archive/tracks/v5_0_2fa_implementation/](./conductor/archive/tracks/v5_0_2fa_implementation/)*

## [x] Track: Fix User Deletion Orphaned Files
*Link: [./conductor/archive/tracks/fix_user_deletion_orphaned_files/](./conductor/archive/tracks/fix_user_deletion_orphaned_files/)*

## [x] Track: Release Candidate v5.0.0-rc1 Preparation
*Link: [./conductor/archive/tracks/v5_0_0_rc1_preparation/](./conductor/archive/tracks/v5_0_0_rc1_preparation/)*






## [x] Track: Setup Environnement de Test Email avec MailHog.
*Link: [./conductor/archive/email_testing_setup_mailhog/](./conductor/archive/email_testing_setup_mailhog/)*

## [x] Track: Améliorations de la gestion utilisateur et notifications (v4.27.0).
*Link: [./conductor/archive/user_management_updates_v4_27_0/](./conductor/archive/user_management_updates_v4_27_0/)*

## [x] Track: Augmentation de la couverture de tests sur les modules critiques.
*Link: [./conductor/archive/test_coverage_improvement_20251225/](./conductor/archive/test_coverage_improvement_20251225/)*

## [x] Track: Implement the Admin Panel UI (HTML/JS) to interface with the new admin API endpoints, featuring a user table, filters, and bulk action controls.
*Archived: [./conductor/archive/admin_panel_e2e_20251224/](./conductor/archive/admin_panel_e2e_20251224/)*