#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024 Daniel Wagner <wagi@monom.org>

set -e

# Set directories for generated files
CERT_DIR="$1/certs"
KEY_DIR="$1/keys"
OUTPUT_DIR="$2"

mkdir -p "$CERT_DIR" "$KEY_DIR"

# Set the subject for the certificates
SUBJECT="/C=US/ST=California/L=San Francisco/O=TestCompany/CN=tty-clipboard-server"

# Create OpenSSL config for signing
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

# Copy certificates to output directory so meson can track them
if [ -n "$OUTPUT_DIR" ]; then
    cp "$CERT_DIR/ca.crt" "$OUTPUT_DIR/"
    cp "$CERT_DIR/server.crt" "$OUTPUT_DIR/"
    cp "$CERT_DIR/client.crt" "$OUTPUT_DIR/"
    cp "$KEY_DIR/ca.key" "$OUTPUT_DIR/"
    cp "$KEY_DIR/server.key" "$OUTPUT_DIR/"
    cp "$KEY_DIR/client.key" "$OUTPUT_DIR/"
fi

echo "Certificate generation complete!"
