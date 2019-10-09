
#!/bin/sh

#####
# (1) Install SSL dependencies
#####
apk add --no-cache libressl


#####
# (2) Create SSL artifacts (see: https://dunne.io/vault-and-self-signed-ssl-certificates)
#####

# Clean up SSL workspace
cd /vault/config/ssl
# Configure SSL at the OS level to trust the new certs
cp root-cert.pem vault-cert.pem /usr/local/share/ca-certificates/
# Clean up temp files
update-ca-certificates

vault server -config /vault/config/config.hcl
