package com.datapipe.jenkins.vault;

import com.bettercloud.vault.SslConfig;
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

    private transient VaultConfig config;


    public void init(String url) {
        init(url, null, false);
    }

    public void init(String url, boolean skipSslVerification) {
        init(url, null, skipSslVerification);
    }

    public void init(String url, VaultCredential credential) {
        init(url, credential, false);
    }

    public void init(String url, VaultCredential credential, boolean skipSslVerification) {

        LOGGER.log(Level.INFO, "Vault Accessor init: " + url + " with credential: " + credential);

        String namespace = "dx_tiaas";

        try {
            config = new VaultConfig()
                    .address(url)
                    .sslConfig(new SslConfig().verify(skipSslVerification).build())
                    .nameSpace(namespace)
                    .build();
            if (credential == null)
                vault = new Vault(config);
            else
                vault = credential.authorizeWithVault(config);
        } catch (VaultException e) {
            throw new VaultPluginException("failed to connect to vault", e);
        }
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
