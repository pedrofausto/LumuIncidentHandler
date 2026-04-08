#!/bin/bash
set -e

CERT_DIR="/certs"
mkdir -p "$CERT_DIR"

# Root CA
openssl genrsa -out "$CERT_DIR/root-ca-key.pem" 2048
openssl req -x509 -new -nodes -key "$CERT_DIR/root-ca-key.pem" -sha256 -days 3650 -out "$CERT_DIR/root-ca.pem" -subj "/C=US/ST=CA/L=Wazuh/O=Wazuh/CN=Wazuh-Root-CA"

# Function to generate node cert
generate_cert() {
    local name=$1
    local dns=$2
    echo "Generating cert for $name ($dns)"
    openssl genrsa -out "$CERT_DIR/$name-key.pem" 2048
    openssl req -new -key "$CERT_DIR/$name-key.pem" -out "$CERT_DIR/$name.csr" -subj "/C=US/ST=CA/L=Wazuh/O=Wazuh/CN=$dns"
    
    cat > "$CERT_DIR/$name.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $dns
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

    openssl x509 -req -in "$CERT_DIR/$name.csr" -CA "$CERT_DIR/root-ca.pem" -CAkey "$CERT_DIR/root-ca-key.pem" -CAcreateserial -out "$CERT_DIR/$name.pem" -days 3650 -sha256 -extfile "$CERT_DIR/$name.ext"
}

# Generate node certs
generate_cert "wazuh.indexer" "wazuh.indexer"
generate_cert "wazuh.manager" "wazuh.manager"
generate_cert "wazuh.dashboard" "wazuh.dashboard"
generate_cert "admin" "admin"

# Copy Root CA for manager as expected by Wazuh
cp "$CERT_DIR/root-ca.pem" "$CERT_DIR/root-ca-manager.pem"

echo "Certificates generated successfully in $CERT_DIR"
