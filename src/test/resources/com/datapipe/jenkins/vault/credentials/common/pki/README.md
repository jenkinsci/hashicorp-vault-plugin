Test-only PKI fixtures (never used outside unit tests): a self-signed root CA, an intermediate CA
signed by the root, and a leaf certificate for `jenkins.example.com` signed by the intermediate.
`leaf-key-pkcs8.pem` and `leaf-key-pkcs1.pem` are the same leaf private key in PKCS#8 and
PKCS#1 (traditional RSA) encoding. `ca-chain.pem` is `intermediate.pem` followed by `root.pem`,
in the order Vault returns `ca_chain`. The CA private keys were discarded after signing.
