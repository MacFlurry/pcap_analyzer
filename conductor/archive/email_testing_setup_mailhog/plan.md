# Track: Setup Environnement de Test Email avec MailHog

Ce track concerne le déploiement de MailHog dans le cluster Kubernetes pour tester les notifications email en environnement de développement.

## Objectifs
- [ ] Déployer MailHog dans le namespace `pcap-analyzer`.
- [ ] Configurer l'application pour utiliser MailHog comme serveur SMTP.
- [ ] Valider l'envoi des emails de registration et d'approbation.
- [ ] Documenter le setup pour les développeurs.

## Plan d'action

### Phase 1: Déploiement MailHog
- [x] Créer le fichier `k8s/mailhog.yaml`. (Fait)
- [x] Appliquer le déploiement MailHog dans le cluster. (Fait)
- [x] Vérifier que le service MailHog est opérationnel. (Fait)

### Phase 2: Configuration Applicative
- [x] Mettre à jour le déploiement `pcap-analyzer` avec les variables d'environnement SMTP pointant vers MailHog. (Fait)
- [x] S'assurer que `MAIL_ENABLED` est à `true`. (Fait)

### Phase 3: Tests et Validation
- [x] Tester le flux d'inscription (Email de Registration). (Fait)
- [x] Tester le flux d'approbation admin (Email d'Approbation). (Fait)
- [x] Vérifier les logs de l'application pour confirmer l'envoi. (Fait via script de debug)
- [x] Valider le rendu des templates HTML dans l'interface MailHog. (Fait)

### Phase 4: Documentation
- [x] Créer `docs/EMAIL_SETUP.md` avec les instructions complètes. (Fait)

## Critères de Succès
- MailHog UI accessible via port-forward ou ingress.
- Emails reçus instantanément dans MailHog lors des actions utilisateur.
- Documentation claire permettant à un nouveau développeur de reproduire le setup.
