# Configuration des Notifications Email

Ce document explique comment configurer et tester le système de notifications email de PCAP Analyzer.

## Environnement de Développement (MailHog)

Pour tester les emails sans serveur SMTP réel, nous utilisons [MailHog](https://github.com/mailhog/MailHog).

### 1. Déploiement dans Kubernetes

Si MailHog n'est pas encore déployé, appliquez le fichier YAML :

```bash
kubectl apply -f k8s/mailhog.yaml
```

### 2. Accès à l'interface Web

Pour voir les emails envoyés, vous devez accéder à l'interface web de MailHog (port 8025).

**Option A : Port-Forward (Recommandé)**
```bash
kubectl port-forward -n pcap-analyzer svc/mailhog 8025:8025
```
Accédez ensuite à : [http://localhost:8025](http://localhost:8025)

**Option B : Ingress**
Si un Ingress est configuré pour `mailhog.local`, assurez-vous que votre fichier `/etc/hosts` est à jour.

### 3. Configuration de l'Application

L'application doit être configurée avec les variables suivantes :

```yaml
SMTP_HOST: "mailhog.pcap-analyzer.svc.cluster.local"
SMTP_PORT: "1025"
SMTP_TLS: "false"
SMTP_SSL: "false"
MAIL_ENABLED: "true"
MAIL_FROM: "noreply@pcap-analyzer.com"
MAIL_FROM_NAME: "PCAP Analyzer - Dev"
```

## Environnement de Production

En production, nous utilisons **Proton Mail SMTP** avec un domaine personnalisé (pcaplab.com).

### Configuration Proton Mail (Configuration Actuelle)

PCAP Analyzer est configuré pour utiliser Proton Mail avec le domaine `pcaplab.com`.

#### Variables d'Environnement

| Variable | Valeur | Description |
|----------|--------|-------------|
| `SMTP_HOST` | `smtp.protonmail.ch` | Serveur SMTP Proton Mail |
| `SMTP_PORT` | `587` | Port SMTP avec STARTTLS |
| `SMTP_TLS` | `true` | Utiliser STARTTLS |
| `SMTP_USERNAME` | `contact@pcaplab.com` | Adresse email d'envoi |
| `SMTP_PASSWORD` | `<SMTP Token>` | Token SMTP (généré dans Proton Mail) |
| `MAIL_ENABLED` | `true` | Activer les notifications email |
| `MAIL_FROM` | `contact@pcaplab.com` | Adresse d'expédition |
| `MAIL_FROM_NAME` | `PCAP Analyzer` | Nom de l'expéditeur |
| `SUPPORT_EMAIL` | `support@pcaplab.com` | Email de support (affiché dans les templates) |
| `APP_BASE_URL` | `http://pcaplab.com` | URL de base pour les liens dans les emails |

#### Configuration Kubernetes

Les credentials SMTP sont stockés dans un secret Kubernetes :

```bash
kubectl create secret generic proton-smtp-credentials \
  --from-literal=username=contact@pcaplab.com \
  --from-literal=password=<VOTRE_TOKEN_SMTP> \
  -n pcap-analyzer
```

**Note importante** : Le token SMTP Proton Mail se génère dans les paramètres de votre compte Proton Mail, section "IMAP/SMTP". Il s'agit d'un token d'application, pas de votre mot de passe principal.

#### Configuration Helm Chart

Le Helm chart inclut la configuration email dans `values.yaml` :

```yaml
email:
  enabled: true
  smtp:
    host: smtp.protonmail.ch
    port: 587
    tls: true
    from: contact@pcaplab.com
    fromName: "PCAP Analyzer"
  credentials:
    existingSecret: proton-smtp-credentials
    usernameKey: username
    passwordKey: password
  supportEmail: support@pcaplab.com
  appBaseUrl: http://pcaplab.com
```

Le déploiement injecte automatiquement ces variables dans les pods.

### Autres Fournisseurs SMTP

Si vous souhaitez utiliser un autre fournisseur (AWS SES, SendGrid, Gmail, etc.), modifiez les variables d'environnement dans le Helm chart :

| Fournisseur | SMTP_HOST | SMTP_PORT | Notes |
|-------------|-----------|-----------|-------|
| **AWS SES** | `email-smtp.us-east-1.amazonaws.com` | `587` | Nécessite des credentials IAM SMTP |
| **SendGrid** | `smtp.sendgrid.net` | `587` | Username: `apikey`, Password: Clé API |
| **Gmail** | `smtp.gmail.com` | `587` | Nécessite un mot de passe d'application |
| **Mailgun** | `smtp.mailgun.org` | `587` | Credentials depuis le dashboard Mailgun |

## Templates d'Emails

Les templates sont situés dans `app/templates/emails/` et utilisent le moteur **Jinja2**.

- `registration_confirmation.html` : Envoyé immédiatement après l'inscription.
- `account_approved.html` : Envoyé après l'approbation par un administrateur.

### Personnalisation

Vous pouvez modifier les styles CSS directement dans les fichiers HTML. Les variables disponibles dans les templates sont :
- `username`
- `email`
- `created_at` / `approved_at`
- `login_url`
- `support_email`

## Troubleshooting

### Les emails ne sont pas envoyés
1. Vérifiez `MAIL_ENABLED=true`.
2. Vérifiez les logs de l'application : `kubectl logs -n pcap-analyzer -l app.kubernetes.io/name=pcap-analyzer`.
3. Testez la connectivité réseau entre le pod `pcap-analyzer` et le service `mailhog`.

### Erreur de rendu de template
Si une variable est manquante ou mal formatée dans `EmailService`, Jinja2 peut lever une erreur. Vérifiez la méthode `_send_email` dans `app/services/email_service.py`.

## Conformité RGPD

- Les emails ne doivent pas contenir de mots de passe en clair.
- Les adresses email sont stockées de manière sécurisée en base de données.
- L'utilisateur peut demander la suppression de ses données (ce qui supprimera également son adresse email).
