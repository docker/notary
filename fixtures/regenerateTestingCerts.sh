#!/usr/bin/env bash

# Script to be used for generating testing certs only for notary-server and notary-signer
# Will also create a root-ca and intermediate-ca, deleting those keys when finished

OPENSSLCNF=
for path in /etc/openssl/openssl.cnf /etc/ssl/openssl.cnf /usr/local/etc/openssl/openssl.cnf; do
    if [[ -e ${path} ]]; then
        OPENSSLCNF=${path}
    fi
done
if [[ -z ${OPENSSLCNF} ]]; then
    printf "Could not find openssl.cnf"
    exit 1
fi

# First generates root-ca
openssl genrsa -out "root-ca.key" 4096
openssl req -new -key "root-ca.key" -out "root-ca.csr" -sha256 \
        -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=Notary Testing CA'

openssl x509 -req -days 3650 -in "root-ca.csr" -signkey "root-ca.key" -sha256 \
        -out "root-ca.crt" -extfile "cert_config.cnf" -extensions root_ca
cp "root-ca.crt" "../cmd/notary/root-ca.crt"

rm "root-ca.csr"

###############################################################################

# Then generate intermediate-ca
openssl genrsa -out "intermediate-ca.key" 4096
openssl req -new -key "intermediate-ca.key" -out "intermediate-ca.csr" -sha256 \
        -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=Notary Intermediate Testing CA'

openssl x509 -req -days 3650 -in "intermediate-ca.csr" -sha256 \
        -CA "root-ca.crt" -CAkey "root-ca.key"  -CAcreateserial \
        -out "intermediate-ca.crt" -extfile "cert_config.cnf" -extensions intermediate_ca

rm "intermediate-ca.csr"
rm "root-ca.key" "root-ca.srl"

###############################################################################

# Then generate notary-server
# Use the existing notary-server key
openssl req -new -key "notary-server.key" -out "notary-server.csr" -sha256 \
        -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=notary-server'

openssl x509 -req -days 750 -in "notary-server.csr" -sha256 \
        -CA "intermediate-ca.crt" -CAkey "intermediate-ca.key"  -CAcreateserial \
        -out "notary-server.crt" -extfile "cert_config.cnf" -extensions notary_server
# append the intermediate cert to this one to make it a proper bundle
cat "intermediate-ca.crt" >> "notary-server.crt"

rm "notary-server.csr"

###############################################################################

# Then generate notary-escrow
# Use the existing notary-escrow key
openssl req -new -key "notary-escrow.key" -out "notary-escrow.csr" -sha256 \
        -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=notary-escrow'

openssl x509 -req -days 750 -in "notary-escrow.csr" -sha256 \
        -CA "intermediate-ca.crt" -CAkey "intermediate-ca.key"  -CAcreateserial \
        -out "notary-escrow.crt" -extfile "cert_config.cnf" -extensions notary_escrow
# append the intermediate cert to this one to make it a proper bundle
cat "intermediate-ca.crt" >> "notary-escrow.crt"

rm "notary-escrow.csr"

###############################################################################

# Then generate notary-signer
# Use the existing notary-signer key
openssl req -new -key "notary-signer.key" -out "notary-signer.csr" -sha256 \
        -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=notary-signer'

openssl x509 -req -days 750 -in "notary-signer.csr" -sha256 \
        -CA "intermediate-ca.crt" -CAkey "intermediate-ca.key"  -CAcreateserial \
        -out "notary-signer.crt" -extfile "cert_config.cnf" -extensions notary_signer
# append the intermediate cert to this one to make it a proper bundle
cat "intermediate-ca.crt" >> "notary-signer.crt"

rm "notary-signer.csr"

###############################################################################

# Then generate secure.example.com
# Use the existing secure.example.com key
openssl req -new -key "secure.example.com.key" -out "secure.example.com.csr" -sha256 \
        -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=secure.example.com'

openssl x509 -req -days 750 -in "secure.example.com.csr" -sha256 \
        -CA "intermediate-ca.crt" -CAkey "intermediate-ca.key"  -CAcreateserial \
        -out "secure.example.com.crt" -extfile "cert_config.cnf" -extensions secure.example.com
rm "secure.example.com.csr"

# generate self-signed_docker.com-notary.crt and self-signed_secure.example.com
for selfsigned in self-signed_docker.com-notary self-signed_secure.example.com; do
        subj='/O=Docker/CN=docker.com\/notary'
        if [[ "${selfsigned}" =~ .*example.com ]]; then
                subj='/O=secure.example.com/CN=secure.example.com'
        fi

        openssl ecparam -name prime256v1 -genkey -out "${selfsigned}.key"
        openssl req -new -key "${selfsigned}.key" -out "${selfsigned}.csr" -sha256 -subj "${subj}"

        openssl x509 -req -days 750 -in "${selfsigned}.csr" -signkey "${selfsigned}.key" \
                -out "${selfsigned}.crt" -extfile "cert_config.cnf" -extensions selfsigned

        rm "${selfsigned}.csr" "${selfsigned}.key"
done

###############################################################################

# Then generate clientapi-server
# Use the existing clientapi-server key
openssl req -new -key "clientapi-server.key" -out "clientapi-server.csr" -sha256 \
        -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=clientapi-server'

openssl x509 -req -days 750 -in "clientapi-server.csr" -sha256 \
        -CA "intermediate-ca.crt" -CAkey "intermediate-ca.key"  -CAcreateserial \
        -out "clientapi-server.crt" -extfile "cert_config.cnf" -extensions clientapi_server
# append the intermediate cert to this one to make it a proper bundle
cat "intermediate-ca.crt" >> "clientapi-server.crt"

rm "clientapi-server.csr"

###############################################################################
# Cleanup

rm "intermediate-ca.key" "intermediate-ca.srl"
