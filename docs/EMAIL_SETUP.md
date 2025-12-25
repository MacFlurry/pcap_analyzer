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

En production, vous devez utiliser un vrai fournisseur SMTP (AWS SES, SendGrid, Gmail, etc.).

### Configuration recommandée (Variables d'Environnement)

| Variable | Description | Exemple |
|----------|-------------|---------|
| `SMTP_HOST` | Serveur SMTP | `smtp.sendgrid.net` |
| `SMTP_PORT` | Port SMTP | `587` (TLS) ou `465` (SSL) |
| `SMTP_USERNAME` | Nom d'utilisateur SMTP | `apikey` |
| `SMTP_PASSWORD` | Mot de passe ou Clé API | `SG.xxx...` |
| `SMTP_TLS` | Utiliser STARTTLS | `true` |
| `SMTP_SSL` | Utiliser SSL direct | `false` |
| `MAIL_FROM` | Adresse d'expédition | `noreply@votre-domaine.com` |
| `APP_BASE_URL` | URL de base pour les liens | `https://pcap.votre-domaine.com` |

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
