# Create a CA root certificate and key
openssl req -newkey rsa:2048 -days 3650 -x509 -nodes -out root-cert.pem -keyout root-privkey.pem -subj '/C=DK/ST=Denmark/L=Copenhagen/O=Jenkins/CN=localhost'
# Create a private key, and a certificate-signing request
openssl req -newkey rsa:1024 -nodes -out vault-csr.pem -keyout vault-privkey.pem -subj '/C=DK/ST=Denmark/L=Copenhagen/O=Jenkins/CN=localhost'
# Create an X509 certificate for the Vault server
echo 000a > serialfile
touch certindex
openssl ca -batch -config libressl.conf -notext -in vault-csr.pem -out vault-cert.pem
