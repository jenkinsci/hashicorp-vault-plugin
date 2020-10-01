package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Util;
import org.kohsuke.stapler.DataBoundSetter;

public abstract class AbstractVaultTokenCredential
    extends BaseStandardCredentials implements VaultCredential {

    @CheckForNull
    private String namespace;

    protected AbstractVaultTokenCredential(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }

    /**
     * Get Vault namespace.
     * @return vault namespace or null
     */
    @CheckForNull
    public String getNamespace() {
        return namespace;
    }

    /**
     * Set namespace where auth method is mounted. If set to "/"
     * the root namespace is explicitly forced, otherwise the
     * namespace from the secret credential vault config is used.
     * @param namespace vault namespace
     */
    @DataBoundSetter
    public void setNamespace(String namespace) {
        this.namespace = Util.fixEmptyAndTrim(namespace);
    }

    protected abstract String getToken(Vault vault);

    @Override
    public Vault authorizeWithVault(VaultConfig config) {
        try {
            VaultConfig authCfg = config;
            // override vault credential namespace
            if (namespace != null) {
                authCfg = new VaultConfig()
                    .address(config.getAddress())
                    .engineVersion(config.getGlobalEngineVersion())
                    .prefixPathDepth(config.getPrefixPathDepth())
                    .sslConfig(config.getSslConfig())
                    .secretsEnginePathMap(config.getSecretsEnginePathMap())
                    .openTimeout(config.getOpenTimeout())
                    .readTimeout(config.getReadTimeout());
                if (!namespace.trim().equals("/")) {
                    authCfg = authCfg.nameSpace(namespace);
                }
                authCfg.build();
            }
            String token = getToken(new Vault(authCfg));
            return new Vault(config.token(token));
        } catch (VaultException ve) {
            throw new VaultPluginException("failed to authorize vault credentials", ve);
        }
    }
}
