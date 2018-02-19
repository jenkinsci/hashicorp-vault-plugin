package com.datapipe.jenkins.vault;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;

import java.util.Map;

public class VaultAccessor {
    private Vault vault;

    private VaultConfig config;

    public void init(String url) {
        init(url, false);
    }

    public void init(String url, boolean skipSslVerification) {
        try {
            config = new VaultConfig(url).sslVerify(skipSslVerification)
                    .build();
            vault = new Vault(config);
        } catch (VaultException e) {
            throw new VaultPluginException("failed to connect to vault", e);
        }
    }

    public void auth(VaultCredential vaultCredential) {
        vault = vaultCredential.authorizeWithVault(vault, config);
    }

    public Map<String, String> read(String path) {
        try {
            return vault.logical().read(path).getData();
        } catch (VaultException e) {
            throw new VaultPluginException("could not read from vault: " + e.getMessage() + " at path: " + path, e);
        }
    }
}
