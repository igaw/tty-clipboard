#!/bin/bash
#!/bin/bash

# Set directories for generated files
CERT_DIR="./certs"
KEY_DIR="./keys"
mkdir -p $CERT_DIR $KEY_DIR

# Fetch passwords from the keyring
CA_PASSWORD=$(keyring get tty-clipboard ca)
SERVER_PASSWORD=$(keyring get tty-clipboard server)
CLIENT_PASSWORD=$(keyring get tty-clipboard client)

if [[ -z "$CA_PASSWORD" || -z "$SERVER_PASSWORD" || -z "$CLIENT_PASSWORD" ]]; then
  echo "One or more passwords are missing from the keyring. Please make sure they are added."
  exit 1
fi

# Set the subject for the certificates
SUBJECT="/C=US/ST=California/L=San Francisco/O=MyCompany/CN=localhost"

# Generate the CA private key
echo "Generating the Certificate Authority (CA) private key..."
openssl genpkey -algorithm RSA -out $KEY_DIR/ca.key -aes256 -pass pass:$CA_PASSWORD

# Generate the CA certificate (self-signed)
echo "Generating the Certificate Authority (CA) certificate..."
openssl req -key $KEY_DIR/ca.key -new -x509 -out $CERT_DIR/ca.crt -days 3650 -subj "$SUBJECT" --passin pass:$CA_PASSWORD

# Generate the server private key
echo "Generating the server private key..."
openssl genpkey -algorithm RSA -out $KEY_DIR/server.key -pass pass:$SERVER_PASSWORD

# Generate the server certificate signing request (CSR)
echo "Generating the server CSR..."
openssl req -key $KEY_DIR/server.key -new -out $CERT_DIR/server.csr -subj "$SUBJECT" -passin pass:$SERVER_PASSWORD

# Sign the server certificate with the CA's private key
echo "Generating the server certificate..."
openssl x509 -req -in $CERT_DIR/server.csr -CA $CERT_DIR/ca.crt -CAkey $KEY_DIR/ca.key -CAcreateserial -out $CERT_DIR/server.crt -days 365 -sha256 --passin pass:$SERVER_PASSWORD

# Generate the client private key
echo "Generating the client private key..."
openssl genpkey -algorithm RSA -out $KEY_DIR/client.key -pass pass:$CLIENT_PASSWORD

# Generate the client certificate signing request (CSR)
echo "Generating the client CSR..."
openssl req -key $KEY_DIR/client.key -new -out $CERT_DIR/client.csr -subj "$SUBJECT" -passin pass:$CLIENT_PASSWORD

# Sign the client certificate with the CA's private key
echo "Generating the client certificate..."
openssl x509 -req -in $CERT_DIR/client.csr -CA $CERT_DIR/ca.crt -CAkey $KEY_DIR/ca.key -CAcreateserial -out $CERT_DIR/client.crt -days 365 -sha256 --passin pass:$CLIENT_PASSWORD

# Clean up CSR files as they are no longer needed
rm -f $CERT_DIR/server.csr $CERT_DIR/client.csr

# Display the generated certificates and keys
echo "CA certificate: $CERT_DIR/ca.crt"
echo "Server certificate: $CERT_DIR/server.crt"
echo "Server private key: $KEY_DIR/server.key"
echo "Client certificate: $CERT_DIR/client.crt"
echo "Client private key: $KEY_DIR/client.key"

# Print a success message
echo "Certificate generation complete!"
