# Project Tracks

This file tracks all major tracks for the project. Each track has its own detailed plan in its respective folder.

---

## [x] Track: HTML Report Timestamp Discrepancy Fix (v5.4.5)
*Context: Fix discrepancy between CLI (Premier SYN) and HTML report (First Retrans) by integrating stateful SYN analysis data into the HTML exporter.*
*Link: [./conductor/archive/tracks/html_report_timestamp_fix_v545/](./conductor/archive/tracks/html_report_timestamp_fix_v545/)*
*Version: v5.4.5 (PATCH)*
*Priority: MEDIUM 🟡*
*Status: ✅ COMPLETED*

## [x] Track: Frame Numbering Bug Fix (v5.2.4)
*Context: Fix triple root cause bug - frame numbers didn't match Wireshark (parser counted only IP packets, CLI passed wrong counter, handshake analyzer recorded last SYN-ACK)*
*Link: [./conductor/archive/tracks/frame_numbering_bug_v524/](./conductor/archive/tracks/frame_numbering_bug_v524/)*
*Version: v5.2.4 (PATCH)*
*Priority: CRITICAL 🔴*
*Status: ✅ COMPLETED*

## [x] Track: SYN Retransmission Packet Timeline Bug Fix
*Context: Fix critical data integrity bug where packet timeline shows frames from wrong TCP streams*
*Link: [./conductor/archive/tracks/syn_retrans_packet_timeline_bug/](./conductor/archive/tracks/syn_retrans_packet_timeline_bug/)*
*Version: v5.2.3 (PATCH)*
*Priority: CRITICAL 🔴*
*Status: ✅ COMPLETED*

## [x] Track: Fix Retransmission Detection Over-Sensitivity
*Context: PCAP Analyzer detects 59% more retransmissions than tshark due to over-sensitive hybrid dpkt+Scapy algorithm - false positives, wrong Fast/RTO classification, missing spurious detection*
*Link: [./conductor/archive/tracks/retransmission_detection_fix_v530/](./conductor/archive/tracks/retransmission_detection_fix_v530/)*
*Version: v5.3.0 (MINOR)*
*Priority: HIGH 🟠*
*Status: ✅ COMPLETED*
*Solution: Implemented tshark backend in v5.4.0 - achieves 100% accuracy (27/27 retrans vs tshark)*

## [x] Track: tshark Backend for 100% Retransmission Detection Accuracy
*Context: Implement hybrid tshark/builtin backend with auto-detection for maximum accuracy*
*Link: [./conductor/archive/tracks/tshark_backend_v540/](./conductor/archive/tracks/tshark_backend_v540/)*
*Version: v5.4.0 (MINOR)*
*Priority: HIGH 🟠*
*Status: ✅ COMPLETED*
*Achievement: 100% accuracy (27/27 retrans), auto-detection with graceful fallback, Docker image integration*

## [ ] Track: Production VPS Deployment with HTTPS
*Context: Deploy to production VPS with Let's Encrypt automated TLS (pending infrastructure)*
*Link: [./conductor/tracks/vps_deployment_https/](./conductor/tracks/vps_deployment_https/)*

## [ ] Track: Modern Toast Notification System
*Context: Implement modern toast notifications to replace generic JavaScript alerts*
*Link: [./conductor/tracks/modern_toast_notification_system/](./conductor/tracks/modern_toast_notification_system/)*
*Version: v5.3.0 (MINOR)*

## [x] Track: Version Synchronization & v5.0.0-rc2 Release

## [x] Track: Password Reset Functionality
*Link: [./conductor/archive/tracks/password_reset/](./conductor/archive/tracks/password_reset/)*

## [x] Track: Fix User Menu Not Showing After Password Change
*Link: [./conductor/archive/tracks/fix_password_change_ui_bug/](./conductor/archive/tracks/fix_password_change_ui_bug/)*

## [x] Track: Add Owner Column in History View for Admins
*Link: [./conductor/archive/tracks/add_owner_column_history/](./conductor/archive/tracks/add_owner_column_history/)*

## [x] Track: Add Cancel Button to 2FA Setup Modal
*Link: [./conductor/archive/tracks/add_cancel_button_2fa_modal/](./conductor/archive/tracks/add_cancel_button_2fa_modal/)*

## [x] Track: PCAP Validation with User-Friendly Error Messages
*Link: [./conductor/archive/tracks/pcap_validation_error_messages/](./conductor/archive/tracks/pcap_validation_error_messages/)*

## [x] Track: Let's Encrypt with cert-manager on Kubernetes
*Link: [./conductor/archive/tracks/letsencrypt_certmanager/](./conductor/archive/tracks/letsencrypt_certmanager/)*

## [x] Assistant Work: v4.28.2 & v4.28.3 - Documentation Email + Production Domain + Fix Dépendances 2FA
*Date: 2025-12-26*
*Report: [./conductor/archive/ASSISTANT_REPORT_v4_28_2_v4_28_3.md](./conductor/archive/ASSISTANT_REPORT_v4_28_2_v4_28_3.md)*

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