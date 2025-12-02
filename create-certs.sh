#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

# Create certs/keys under XDG config so the binaries can find them.
CFG_BASE=${XDG_CONFIG_HOME:-"$HOME/.config"}/tty-clipboard
CERT_DIR="$CFG_BASE/certs"
KEY_DIR="$CFG_BASE/keys"
mkdir -p "$CERT_DIR" "$KEY_DIR"

echo "Using config directory: $CFG_BASE"

# Subject for generated certs
SUBJECT="/C=US/ST=California/L=San Francisco/O=tty-clipboard/CN=tty-clipboard-server"

# Create OpenSSL config for signing (matches tests/setup-test-certs.sh)
cat > "$CERT_DIR/openssl.cnf" << 'EOF'
[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical, keyCertSign, cRLSign

[v3_end]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
EOF

# Generate the CA private key (EC P-256)
echo "Generating the Certificate Authority (CA) private key (EC P-256)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out "$KEY_DIR/ca.key"

# Generate the CA certificate (self-signed)
echo "Generating the Certificate Authority (CA) certificate..."
openssl req -key "$KEY_DIR/ca.key" -new -x509 -out "$CERT_DIR/ca.crt" -days 3650 -subj "$SUBJECT" -config "$CERT_DIR/openssl.cnf" -extensions v3_ca

# Generate the server private key (EC P-256)
echo "Generating the server private key (EC P-256)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out "$KEY_DIR/server.key"

# Generate the server certificate signing request (CSR)
echo "Generating the server CSR..."
openssl req -key "$KEY_DIR/server.key" -new -out "$CERT_DIR/server.csr" -subj "$SUBJECT"

# Sign the server certificate with the CA's private key
echo "Generating the server certificate..."
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$KEY_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/server.crt" -days 365 -sha256 -extfile "$CERT_DIR/openssl.cnf" -extensions v3_end

# Generate the client private key (EC P-256)
echo "Generating the client private key (EC P-256)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out "$KEY_DIR/client.key"

# Generate the client certificate signing request (CSR)
echo "Generating the client CSR..."
openssl req -key "$KEY_DIR/client.key" -new -out "$CERT_DIR/client.csr" -subj "$SUBJECT"

# Sign the client certificate with the CA's private key
echo "Generating the client certificate..."
openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$KEY_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/client.crt" -days 365 -sha256 -extfile "$CERT_DIR/openssl.cnf" -extensions v3_end

# Clean up CSR and config files as they are no longer needed
rm -f "$CERT_DIR/server.csr" "$CERT_DIR/client.csr" "$CERT_DIR/openssl.cnf"

echo "Certificates created in: $CFG_BASE"
echo "  CA:       $CERT_DIR/ca.crt (key: $KEY_DIR/ca.key)"
echo "  Server:   $CERT_DIR/server.crt (key: $KEY_DIR/server.key)"
echo "  Client:   $CERT_DIR/client.crt (key: $KEY_DIR/client.key)"
echo "Certificate generation complete!"
