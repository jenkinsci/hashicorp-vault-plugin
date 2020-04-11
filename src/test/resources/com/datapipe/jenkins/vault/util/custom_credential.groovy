package com.datapipe.jenkins.vault.util

import hudson.util.Secret
import com.cloudbees.plugins.credentials.CredentialsScope
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential

VaultTokenCredential customCredential = new VaultTokenCredential(
    CredentialsScope.GLOBAL,
    'custom-credential',
    'My Custom Credential',
    Secret.fromString('#VAULT_TOKEN#')
)

//noinspection GrPackage
node {
    def secrets = [
        [
            path: 'kv-v1/admin',
            secretValues: [
                [envVar: 'testing', vaultKey: 'key1']
            ]
        ]
    ]
    def configuration = [
        vaultCredential: customCredential,
        skipSslVerification: true // We redefine configuration and TLS Verification isn't merged from parent
    ]
    withVault([configuration: configuration, vaultSecrets: secrets]) {
        echo "${env.testing}"
    }
}
