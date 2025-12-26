# Track: Fix User Deletion Orphaned Files

Suppression des fichiers physiques (PCAP, rapports) lors de la suppression d'un utilisateur par l'administrateur.

## Objectifs
- [x] Modifier l'endpoint `DELETE /api/admin/users/{user_id}` pour supprimer les fichiers sur disque.
- [x] Implémenter une vérification de sécurité sur les chemins de fichiers pour éviter les traversées de répertoire.
- [x] Ajouter une tâche de cleanup périodique pour les fichiers orphelins (sécurité supplémentaire).
- [x] Ajouter des tests unitaires et d'intégration.

## Plan d'action
1. [x] **Analyse** : Identifier tous les types de fichiers générés par tâche (PCAP, HTML, JSON).
2. [x] **Backend** :
    - Récupérer la liste des tâches de l'utilisateur avant sa suppression.
    - Supprimer les fichiers PCAP dans `uploads/`.
    - Supprimer les rapports HTML/JSON dans `reports/`.
    - Gérer les erreurs de suppression (log sans bloquer la suppression du compte).
3. [x] **Cleanup périodique** : Mettre à jour `CleanupScheduler` pour détecter les fichiers sans record en base.
4. [x] **Validation** : Vérifier manuellement et via tests automatiques.

