package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import java.util.List;

public abstract class AbstractVaultTokenCredential
    extends BaseStandardCredentials implements VaultCredential {

    protected AbstractVaultTokenCredential(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }

    protected abstract String getToken(Vault vault);

    @Override
    public VaultAuthorizationResult authorizeWithVault(VaultConfig config, List<String> policies) {
        Vault vault = new Vault(config);
        String token = getToken(vault);
        return new VaultAuthorizationResult(new Vault(config.token(token)), token);
    }
}
