
#!/bin/sh

#####
# (1) Install SSL dependencies
#####
apk add --no-cache libressl


#####
# (2) Create SSL artifacts (see: https://dunne.io/vault-and-self-signed-ssl-certificates)
#####
SSL_WORKSPACE=/vault/config/ssl
LIBRESSL_CONFIG_FILE=/vault/config/libressl.conf

# Clean up SSL workspace
cd ${SSL_WORKSPACE}
# Clean Up temp files
rm -f ${SSL_WORKSPACE}/*.pem ${SSL_WORKSPACE}/serialfile* ${SSL_WORKSPACE}/certindex*

# Fix for Docker in Docker tests
ADDITIONNAL_TEST_SAN_COUNT=3
if [ ! -z "${ADDITIONNAL_TEST_SAN}" ]
then
  for SAN in ${ADDITIONNAL_TEST_SAN}
  do
    echo "DNS.${ADDITIONNAL_TEST_SAN_COUNT} = ${SAN}" >> $LIBRESSL_CONFIG_FILE
    ADDITIONNAL_TEST_SAN_COUNT=$((ADDITIONNAL_TEST_SAN_COUNT+1))
  done
fi

# Create a CA root certificate and key
openssl req -newkey rsa:2048 -days 3650 -x509 -nodes -out root-cert.pem -keyout root-privkey.pem -subj '/C=DK/ST=Denmark/L=Copenhagen/O=Jenkins/CN=localhost'

# Create a private key, and a certificate-signing request
openssl req -newkey rsa:1024 -nodes -out vault-csr.pem -keyout vault-privkey.pem -subj '/C=DK/ST=Denmark/L=Copenhagen/O=Jenkins/CN=localhost'

# Create an X509 certificate for the Vault server
echo 000a > serialfile
> certindex
openssl ca -batch -config $LIBRESSL_CONFIG_FILE -notext -in vault-csr.pem -out vault-cert.pem

# Configure SSL at the OS level to trust the new certs
cp root-cert.pem vault-cert.pem /usr/local/share/ca-certificates/
update-ca-certificates
vault server -config /vault/config/config.hcl
