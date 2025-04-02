package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.api.Auth;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Abstract Vault token credential that authenticates with the vault server to retrieve the
 * authentication token. This credential type can explicitly configure the namespace which
 * the authentication method is mounted.
 */
public abstract class AbstractAuthenticatingVaultTokenCredential extends
    AbstractVaultTokenCredentialWithExpiration {

    @CheckForNull
    private String namespace;

    protected AbstractAuthenticatingVaultTokenCredential(CredentialsScope scope, String id,
        String description) {
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

    @Override
    protected Auth getVaultAuth(@NonNull Vault vault) {
        // set authentication namespace if configured for this credential.
        // importantly, this will not effect the underlying VaultConfig namespace.
        Auth auth = vault.auth();
        if (namespace != null) {
            if (!namespace.trim().equals("/")) {
                auth.withNameSpace(namespace);
            } else {
                auth.withNameSpace(null);
            }
        }
        return auth;
    }

    @Override
    protected final String getToken(Vault vault) {
        return getToken(getVaultAuth(vault));
    }

    /**
     * Authenticate with vault using this credential and return the token. The {@code auth} client
     * will be configured with this credentials namespace.
     * @param auth vault auth client
     * @return authentication token
     * @throws VaultPluginException if failed to authenticate with vault
     */
    protected abstract String getToken(@NonNull Auth auth);
}
