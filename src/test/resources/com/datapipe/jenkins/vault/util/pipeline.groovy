package com.datapipe.jenkins.vault.util
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
    withVault([vaultSecrets: secrets]) {
        echo "${env.testing}"
    }
}
