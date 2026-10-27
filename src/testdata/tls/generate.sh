#!/bin/sh
# Regenerates the TLS fixtures used by src/tls_tests.rs (requires OpenSSL 3).
#
# EMOVTLSCAG3B.spki.der is copied verbatim from rustls-webpki 0.103.16
# (src/data/distrusted/), sha256
# 7f09de2d155cc9fbc2dc4585f2c134ea3fc04ea9d9b3e31fa2d6bf9fdc0a02a2. It is one of
# the distrusted eMudhra intermediate CA public keys; only the public key is
# used here.
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Test root CA. Its private key only lives in $tmp.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/root.key"
openssl req -x509 -new -key "$tmp/root.key" -sha256 -days 36500 \
    -subj "/CN=cloudflare-ddns test root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" \
    -out "$tmp/root.pem"
openssl x509 -in "$tmp/root.pem" -outform DER -out root.der

cat > "$tmp/leaf.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
EOF

# Server key, used by the test server for both leaves.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/leaf.key"
openssl pkcs8 -topk8 -nocrypt -in "$tmp/leaf.key" -outform DER -out leaf.key.der
openssl req -new -key "$tmp/leaf.key" -subj "/CN=127.0.0.1" -out "$tmp/leaf.csr"

# Control leaf: a valid chain to the test root.
openssl x509 -req -in "$tmp/leaf.csr" -CA "$tmp/root.pem" -CAkey "$tmp/root.key" \
    -set_serial 2 -days 36500 -sha256 -extfile "$tmp/leaf.ext" \
    -outform DER -out leaf.der

# Leaf whose public key is the distrusted eMudhra key, issued by the test root.
{ printf '\060\166'; cat EMOVTLSCAG3B.spki.der; } |
    openssl pkey -pubin -inform DER -out "$tmp/emudhra.pem"
openssl x509 -req -in "$tmp/leaf.csr" -CA "$tmp/root.pem" -CAkey "$tmp/root.key" \
    -force_pubkey "$tmp/emudhra.pem" \
    -set_serial 3 -days 36500 -sha256 -extfile "$tmp/leaf.ext" \
    -outform DER -out emudhra-key-leaf.der
