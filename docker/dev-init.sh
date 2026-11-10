#!/bin/sh
# One-shot initialisation of the dev stack: random secrets for the pool gateway and one
# shared MITM CA for the session proxy (DER files) and the control plane (PEM file). Both
# components load it in `file` mode, so no `generate`-mode data_dir has to be shared.
# Idempotent: existing files are kept. Not for production: generate and store secrets and
# the CA with your own tooling there.
set -eu

secrets=/etc/proxyx/secrets
ca=/ca

for name in admin-token prober-token probe-key; do
    if [ ! -s "$secrets/$name" ]; then
        openssl rand -hex 32 > "$secrets/$name"
        echo "created $secrets/$name"
    fi
done

if [ ! -s "$ca/ca.der" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
        -subj "/CN=ProxyX dev CA/O=ProxyX" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
        -addext "subjectKeyIdentifier=hash" \
        -keyout "$ca/ca.key.pem" -out "$ca/ca.pem"
    openssl x509 -in "$ca/ca.pem" -outform DER -out "$ca/ca.der"
    openssl pkcs8 -topk8 -nocrypt -in "$ca/ca.key.pem" -outform DER -out "$ca/ca.key.der"
    echo "created the dev CA in $ca"
fi

chown -R 10001:10001 "$secrets" "$ca"
chmod 0400 "$secrets"/* "$ca"/*.key.*
chmod 0444 "$ca/ca.pem" "$ca/ca.der"
