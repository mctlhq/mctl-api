#!/bin/sh
# Local CA and a server certificate for the edge proxy. Synthetic, throwaway.
# usage: gen-certs.sh <outdir>
set -e
out=$1; mkdir -p "$out"; cd "$out"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mig-local-ca" -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=api.mig.test" -keyout edge.key -out edge.csr 2>/dev/null
printf 'subjectAltName=DNS:api.mctl.ai,DNS:api.mig.test,DNS:api.github.com,DNS:localhost\n' > ext.cnf
openssl x509 -req -in edge.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out edge.pem 2>/dev/null
chmod 644 ca.pem edge.pem; chmod 600 ca.key edge.key
echo "certs in $out"
