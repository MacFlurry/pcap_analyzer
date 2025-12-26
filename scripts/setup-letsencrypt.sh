#!/bin/bash
set -e

echo "🔐 Setting up Let's Encrypt with cert-manager..."

# Install cert-manager
echo "📦 Installing cert-manager..."
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.crds.yaml
helm repo add jetstack https://charts.jetstack.io --force-update
# Check if already installed
if helm list -n cert-manager | grep -q cert-manager; then
    echo "cert-manager already installed, upgrading..."
    helm upgrade cert-manager jetstack/cert-manager \
      --namespace cert-manager \
      --version v1.14.0 \
      --wait
else
    helm install cert-manager jetstack/cert-manager \
      --namespace cert-manager \
      --create-namespace \
      --version v1.14.0 \
      --wait
fi

# Apply ClusterIssuers
echo "🎫 Creating ClusterIssuers..."
kubectl apply -f k8s/cert-manager/

# Verify
echo "✅ Verifying cert-manager..."
kubectl get pods -n cert-manager
kubectl get clusterissuer

echo "✅ cert-manager setup complete!"
echo "Next: Deploy application with TLS enabled"
