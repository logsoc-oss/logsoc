#!/bin/bash
# Génération du certificat auto-signé LogSOC Document Signing
set -e
CERT_DIR=/opt/logsoc-web/certs
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

if [ -f logsoc-doc-signing.p12 ]; then
  echo "Certificat deja present:"
  ls -la "$CERT_DIR"
  exit 0
fi

# Clé + certificat auto-signé (10 ans, usage signature document)
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout logsoc-doc-signing.key \
  -out logsoc-doc-signing.crt \
  -subj "/CN=LogSOC Document Signing/O=LogSOC/C=FR" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=digitalSignature,nonRepudiation" \
  -addext "extendedKeyUsage=emailProtection,codeSigning" 2>/dev/null

# Bundle PKCS#12 (mot de passe vide pour automatisation, fichier chmod 600)
openssl pkcs12 -export -out logsoc-doc-signing.p12 \
  -inkey logsoc-doc-signing.key -in logsoc-doc-signing.crt \
  -passout pass:logsoc

chmod 600 logsoc-doc-signing.key logsoc-doc-signing.p12 logsoc-doc-signing.crt
chown root:root logsoc-doc-signing.*

echo "Certificat genere:"
openssl x509 -in logsoc-doc-signing.crt -noout -subject -dates
ls -la "$CERT_DIR"