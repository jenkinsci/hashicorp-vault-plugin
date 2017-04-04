package com.datapipe.jenkins.vault;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import hudson.util.Secret;

import java.util.Map;

public class VaultAccessor {
    private Vault vault;

    private VaultConfig config;

    public void init(String url) {
        try {
            config = new VaultConfig(url).build();
            vault = new Vault(config);
        } catch (VaultException e) {
            e.printStackTrace();
        }
    }

    public void auth(String roleId, Secret secretId) {
        String token = null;
        try {
            token = vault.auth().loginByAppRole("approle", roleId, Secret.toString(secretId)).getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault", e);
        }

        vault = new Vault(config.token(token));
    }

    public Map<String, String> read(String path) {
        try {
            return vault.logical().read(path).getData();
        } catch (VaultException e) {
            throw new VaultPluginException("could not read from vault", e);
        }
    }
}
