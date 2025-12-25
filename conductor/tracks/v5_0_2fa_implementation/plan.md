# Track: Implémentation Authentification à deux facteurs (2FA) (#29)

Ajout d'une couche de sécurité TOTP pour les utilisateurs.

## Objectifs
- [ ] Implémenter la logique TOTP (via `pyotp`).
- [ ] Créer les endpoints d'activation/désactivation du 2FA.
- [ ] Générer des QR Codes pour la configuration initiale.
- [ ] Mettre à jour le flux de login (Challenge 2FA).
- [ ] Gérer les codes de récupération (Backup codes).

## Plan d'action
1. **Backend** : Ajouter le support TOTP dans le modèle User et `user_database.py`.
2. **API** : Créer les routes pour le setup (QR Code) et la validation.
3. **Login** : Modifier `api/token` pour gérer le flux à deux étapes.
4. **Frontend** : Ajouter les formulaires de validation 2FA dans l'interface.
