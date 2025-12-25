# Track: Améliorations de la gestion utilisateur et notifications (v4.27.0)

Ce track regroupe les correctifs et fonctionnalités prévus pour la v4.27.0, notamment la gestion des fichiers orphelins lors de la suppression d'utilisateur et l'implémentation des notifications email.

## Objectifs
- [ ] Résoudre la fuite de stockage lors de la suppression d'utilisateur (RGPD).
- [ ] Implémenter les notifications email pour l'inscription et l'approbation.
- [ ] Ajouter un job de nettoyage périodique pour les fichiers orphelins (Safety Net).

## Plan d'action

### Phase 1: Infrastructure de Notification Email
- [x] Ajouter `fastapi-mail` aux dépendances. (Fait)
- [x] Créer `EmailService` (`app/services/email_service.py`). (Fait)
- [x] Créer les templates HTML pour les emails. (Fait)
- [x] Intégrer les notifications dans les endpoints d'inscription et d'approbation (`app/api/routes/auth.py`). (Fait)

### Phase 2: Correction du Bug de Suppression (RGPD)
- [x] Modifier `delete_user` pour supprimer les fichiers PCAP et rapports du disque avant la suppression en base. (Fait)
- [x] Ajouter un logging d'audit détaillé pour les suppressions de fichiers. (Fait)

### Phase 3: Sécurité et Cleanup Périodique
- [x] Implémenter `cleanup_orphaned_files` dans `app/services/cleanup.py`. (Fait)
- [x] Planifier le job de cleanup quotidien dans le scheduler. (Fait)

### Phase 4: Vérification et Tests
- [x] Créer des tests unitaires pour le `EmailService`. (Fait)
- [x] Créer des tests d'intégration pour le cycle de vie de l'utilisateur (inscription -> approbation -> suppression). (Fait)
- [ ] Vérifier manuellement avec MailHog. (Optionnel, tests automatisés passent)

## Documentation
- [x] Mettre à jour `.env.example` avec les configurations SMTP. (Fait)
- [x] Mettre à jour `CHANGELOG.md`. (Fait)
