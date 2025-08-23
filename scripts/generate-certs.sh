#!/bin/bash

# VPN9 TLS Certificate Generation Script
# This script generates self-signed certificates for development and testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../certs"
DOMAIN_NAME="${VPN9_TLS_DOMAIN:-vpn9-control-plane}"
KEY_SIZE="${VPN9_KEY_SIZE:-2048}"
DAYS_VALID="${VPN9_CERT_DAYS:-365}"

echo "🔐 Generating VPN9 TLS certificates..."
echo "  Domain: ${DOMAIN_NAME}"
echo "  Key size: ${KEY_SIZE} bits"
echo "  Valid for: ${DAYS_VALID} days"
echo "  Output directory: ${CERTS_DIR}"

# Create certificates directory
mkdir -p "${CERTS_DIR}"

# Generate CA private key
echo "📝 Generating CA private key..."
openssl genrsa -out "${CERTS_DIR}/ca.key" ${KEY_SIZE}

# Generate CA certificate
echo "📝 Generating CA certificate..."
openssl req -new -x509 -days ${DAYS_VALID} -key "${CERTS_DIR}/ca.key" -out "${CERTS_DIR}/ca.crt" -subj "/C=US/ST=CA/L=San Francisco/O=VPN9/OU=Development/CN=VPN9 CA"

# Generate server private key
echo "📝 Generating server private key..."
openssl genrsa -out "${CERTS_DIR}/server.key" ${KEY_SIZE}

# Generate server certificate signing request
echo "📝 Generating server certificate signing request..."
openssl req -new -key "${CERTS_DIR}/server.key" -out "${CERTS_DIR}/server.csr" -subj "/C=US/ST=CA/L=San Francisco/O=VPN9/OU=Control Plane/CN=${DOMAIN_NAME}"

# Create server certificate extensions file
cat > "${CERTS_DIR}/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN_NAME}
DNS.2 = localhost
DNS.3 = *.${DOMAIN_NAME}
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate server certificate signed by CA
echo "📝 Generating server certificate..."
openssl x509 -req -in "${CERTS_DIR}/server.csr" -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" -CAcreateserial -out "${CERTS_DIR}/server.crt" -days ${DAYS_VALID} -extfile "${CERTS_DIR}/server.ext"

# Generate client private key (for mTLS if needed)
echo "📝 Generating client private key..."
openssl genrsa -out "${CERTS_DIR}/client.key" ${KEY_SIZE}

# Generate client certificate signing request
echo "📝 Generating client certificate signing request..."
openssl req -new -key "${CERTS_DIR}/client.key" -out "${CERTS_DIR}/client.csr" -subj "/C=US/ST=CA/L=San Francisco/O=VPN9/OU=Agent/CN=vpn9-agent"

# Create client certificate extensions file
cat > "${CERTS_DIR}/client.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF

# Generate client certificate signed by CA
echo "📝 Generating client certificate..."
openssl x509 -req -in "${CERTS_DIR}/client.csr" -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" -CAcreateserial -out "${CERTS_DIR}/client.crt" -days ${DAYS_VALID} -extfile "${CERTS_DIR}/client.ext"

# Set appropriate permissions
chmod 600 "${CERTS_DIR}"/*.key
chmod 644 "${CERTS_DIR}"/*.crt

# Clean up temporary files
rm -f "${CERTS_DIR}"/*.csr "${CERTS_DIR}"/*.ext "${CERTS_DIR}"/*.srl

echo "✅ Certificate generation completed!"
echo ""
echo "📁 Generated files:"
echo "  CA Certificate: ${CERTS_DIR}/ca.crt"
echo "  CA Private Key: ${CERTS_DIR}/ca.key"
echo "  Server Certificate: ${CERTS_DIR}/server.crt"
echo "  Server Private Key: ${CERTS_DIR}/server.key"
echo "  Client Certificate: ${CERTS_DIR}/client.crt"
echo "  Client Private Key: ${CERTS_DIR}/client.key"
echo ""
echo "🔧 Environment variables for testing:"
echo "  export VPN9_TLS_CERT_PATH=${CERTS_DIR}/server.crt"
echo "  export VPN9_TLS_KEY_PATH=${CERTS_DIR}/server.key"
echo "  export VPN9_TLS_CA_CERT_PATH=${CERTS_DIR}/ca.crt"
echo "  export VPN9_TLS_DOMAIN=${DOMAIN_NAME}"
echo ""
echo "⚠️  WARNING: These are self-signed certificates for development only!"
echo "   Do not use in production. Use certificates from a trusted CA instead."