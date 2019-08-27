//noinspection GrPackage
node {
    def secrets = [
        [
            path: 'secret/testing',
            secretValues: [
                [envVar: 'testing', vaultKey: 'value_one']
            ]
        ]
    ]
    withVault([vaultSecrets: secrets]) {
        echo '${env.testing}'
    }
}
