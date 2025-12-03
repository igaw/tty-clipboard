#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

# Default config directory
CFG_BASE=${XDG_CONFIG_HOME:-"$HOME/.config"}/tty-clipboard
CERT_DIR="$CFG_BASE/certs"
KEY_DIR="$CFG_BASE/keys"

# Parse command line arguments
FORCE=false
SHOW_FINGERPRINTS=false

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Generate TLS certificates and keys for tty-clipboard.

Options:
    -f, --force             Force regeneration even if certificates exist
    -p, --fingerprints      Show fingerprints of existing certificates
    -h, --help              Show this help message

Certificates will be created in:
    $CFG_BASE/certs/
    $CFG_BASE/keys/

EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--force)
            FORCE=true
            shift
            ;;
        -p|--fingerprints)
            SHOW_FINGERPRINTS=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# If fingerprints requested, show them and exit
if [ "$SHOW_FINGERPRINTS" = true ]; then
    if [ ! -f "$CERT_DIR/ca.crt" ] || [ ! -f "$CERT_DIR/server.crt" ] || [ ! -f "$CERT_DIR/client.crt" ]; then
        echo "Error: Certificates not found in $CERT_DIR"
        echo "Run without --fingerprints to generate certificates first."
        exit 1
    fi
    
    echo "Certificate Fingerprints:"
    echo ""
    echo "CA Certificate:"
    openssl x509 -in "$CERT_DIR/ca.crt" -noout -fingerprint -sha256
    echo ""
    echo "Server Certificate:"
    openssl x509 -in "$CERT_DIR/server.crt" -noout -fingerprint -sha256
    echo ""
    echo "Client Certificate:"
    openssl x509 -in "$CERT_DIR/client.crt" -noout -fingerprint -sha256
    exit 0
fi

# Check if certificates already exist
if [ -f "$CERT_DIR/ca.crt" ] && [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/client.crt" ] && \
   [ -f "$KEY_DIR/ca.key" ] && [ -f "$KEY_DIR/server.key" ] && [ -f "$KEY_DIR/client.key" ]; then
    if [ "$FORCE" = false ]; then
        echo "Certificates already exist in: $CFG_BASE"
        echo "Use --force to regenerate, or --fingerprints to show fingerprints."
        exit 0
    else
        echo "Force regeneration enabled. Removing existing certificates..."
        rm -f "$CERT_DIR"/{ca.crt,server.crt,client.crt,ca.srl}
        rm -f "$KEY_DIR"/{ca.key,server.key,client.key}
    fi
fi

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

# Set secure permissions
chmod 600 "$KEY_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo "Certificates created in: $CFG_BASE"
echo "  CA:       $CERT_DIR/ca.crt (key: $KEY_DIR/ca.key)"
echo "  Server:   $CERT_DIR/server.crt (key: $KEY_DIR/server.key)"
echo "  Client:   $CERT_DIR/client.crt (key: $KEY_DIR/client.key)"
echo "Certificate generation complete!"
