# Track: Release Candidate v5.0.0-rc1 Preparation

Préparation de la Release Candidate 1 pour la version majeure 5.0.0.
Cette version inclut toutes les fonctionnalités de sécurité (2FA, Password Policy), le workflow d'approbation administrateur, le panneau d'administration, et la configuration SMTP de production.

## Objectifs
- [x] Vérifier l'état actuel (v4.28.3) et la configuration SMTP Proton Mail.
- [x] Vérifier la synchronisation des dépendances (pyproject.toml vs requirements-web.txt).
- [~] Exécuter une suite de tests système (E2E) couvrant les flux critiques.
- [ ] Synchroniser la documentation finale (README, Deployment Guide).
- [ ] Créer le tag `v5.0.0-rc1`.

## Plan d'action
1. **Vérification v4.28.3** :
    - [x] Inspecter `app/services/email_service.py` et `.env.example`.
    - [x] Vérifier `pyproject.toml` pour les dépendances 2FA.
    - [x] Vérifier que les migrations Alembic sont à jour.

2. **Tests Système (E2E)** :
    - [x] Tenter de corriger les erreurs de la suite de tests (Too many open files / Event loop). (4e3c9d0)
    - [x] Simuler le parcours complet : Inscription -> Email -> Approbation Admin -> Email -> Login 2FA -> Analyse -> Cleanup. (fc3af98)

3. **Documentation** :
    - [x] Mettre à jour `README.md` avec le statut v5.0.0-rc1. (aa6e7c8)
    - [x] Vérifier `docs/EMAIL_SETUP.md` (déjà fait en v4.28.2).

4. **Release** :
    - Tagger `v5.0.0-rc1`.
    - Mettre à jour `CHANGELOG.md`.
    - Archiver ce track.
