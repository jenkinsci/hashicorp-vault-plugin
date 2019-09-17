package com.datapipe.jenkins.vault;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.LogicalResponse;
import com.bettercloud.vault.response.VaultResponse;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import java.io.Serializable;
import java.io.File;

public class VaultAccessor implements Serializable {

    private static final long serialVersionUID = 1L;

    private transient Vault vault;

    private transient VaultConfig config;
    private transient SslConfig sslConfig;
    private transient VaultCredential credential;

    public VaultAccessor() {}

    public void init(VaultConfiguration vaultConfig, VaultCredential credential) {
        try {
            config = new VaultConfig()
                .address(vaultConfig.getVaultUrl())
                .engineVersion(vaultConfig.getEngineVersion())
                .sslConfig(new SslConfig()
                    .trustStoreFile(vaultConfig.getSslTrustStore())
                    .verify(vaultConfig.isSkipSslVerification()).build())
                .build();
            if (credential == null) {
                vault = new Vault(config);
            } else {
                vault = credential.authorizeWithVault(config);
            }
        } catch (VaultException e) {
            throw new VaultPluginException("failed to connect to vault", e);
        }
    }

    public LogicalResponse read(String path, Integer engineVersion) {
        try {
            this.config.engineVersion(engineVersion);
            return vault.logical().read(path);
        } catch (VaultException e) {
            throw new VaultPluginException(
                "could not read from vault: " + e.getMessage() + " at path: " + path, e);
        }
    }

    public VaultResponse revoke(String leaseId) {
        try {
            return vault.leases().revoke(leaseId);
        } catch (VaultException e) {
            throw new VaultPluginException(
                "could not revoke vault lease (" + leaseId + "):" + e.getMessage());
        }
    }
}
