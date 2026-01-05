# Track: Implémentation Authentification à deux facteurs (2FA) (#29)

Ajout d'une couche de sécurité TOTP pour les utilisateurs.

## Objectifs
- [x] Implémenter la logique TOTP (via `pyotp`).
- [x] Créer les endpoints d'activation/désactivation du 2FA.
- [x] Générer des QR Codes pour la configuration initiale.
- [x] Mettre à jour le flux de login (Challenge 2FA).
- [x] Gérer les codes de récupération (Backup codes).

## Plan d'action
1. [x] **Backend** : Ajouter le support TOTP dans le modèle User et `user_database.py`.
2. [x] **API** : Créer les routes pour le setup (QR Code) et la validation.
3. [x] **Login** : Modifier `api/token` pour gérer le flux à deux étapes.
4. [x] **Frontend** : Ajouter les formulaires de validation 2FA dans l'interface.

