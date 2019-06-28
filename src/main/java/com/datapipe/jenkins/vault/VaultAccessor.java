package com.datapipe.jenkins.vault;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.LogicalResponse;
import com.bettercloud.vault.response.VaultResponse;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.Serializable;

public class VaultAccessor implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private static final Logger LOGGER = Logger.getLogger(VaultAccessor.class.getName());
	private transient Vault vault;
    private VaultConfig config;
    private VaultCredential credential;

    private int maxRetries = 0;
    private int retryIntervalMilliseconds = 1000;

    public VaultAccessor() {
        this.config = new VaultConfig();
        this.credential = null;
    }

    public VaultAccessor(VaultConfig config, VaultCredential credential) {
        this.config = config;
        this.credential = credential;
    }


    public VaultAccessor init() {
        try {
            config.build();

            if (credential == null)
                vault = new Vault(config).withRetries(maxRetries, retryIntervalMilliseconds);
            else
                vault = credential.authorizeWithVault(config).withRetries(maxRetries, retryIntervalMilliseconds);
        } catch (VaultException e) {
            throw new VaultPluginException("failed to connect to vault", e);
        }
        return this;
    }

    public VaultConfig getConfig() {
        return config;
    }

    public void setConfig(VaultConfig config) {
        this.config = config;
    }

    public VaultCredential getCredential() {
        return credential;
    }

    public void setCredential(VaultCredential credential) {
        this.credential = credential;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(int maxRetries) {
        this.maxRetries = maxRetries;
    }

    public int getRetryIntervalMilliseconds() {
        return retryIntervalMilliseconds;
    }

    public void setRetryIntervalMilliseconds(int retryIntervalMilliseconds) {
        this.retryIntervalMilliseconds = retryIntervalMilliseconds;
    }

    public LogicalResponse read(String path, Integer engineVersion) {
        try {
            this.config.engineVersion(engineVersion);
            return vault.logical().read(path);
        } catch (VaultException e) {
            throw new VaultPluginException("could not read from vault: " + e.getMessage() + " at path: " + path, e);
        }
    }

    public VaultResponse revoke(String leaseId) {
        try {
            return vault.leases().revoke(leaseId);
        } catch (VaultException e) {
            throw new VaultPluginException("could not revoke vault lease (" + leaseId + "):" + e.getMessage());
        }
    }
}
