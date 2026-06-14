#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 3650 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:keycloak,IP:127.0.0.1"
# For a self-signed leaf the cert is its own trust anchor.
cp server.crt ca.pem
echo "wrote server.crt, server.key, ca.pem"
