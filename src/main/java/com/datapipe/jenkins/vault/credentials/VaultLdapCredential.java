package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import hudson.Extension;
import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundConstructor;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

public class VaultLdapCredential extends BaseStandardCredentials implements VaultCredential {

    private final @Nonnull String serviceAccountName;
    private final @Nonnull
    Secret serviceAccountPassword;

    @DataBoundConstructor
    public VaultLdapCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id, @CheckForNull String description, @Nonnull String serviceAccountName, @Nonnull Secret serviceAccountPassword) {
        super(scope, id, description);
        this.serviceAccountName = serviceAccountName;
        this.serviceAccountPassword = serviceAccountPassword;
    }

    @Override
    public Vault authorizeWithVault(Vault vault, VaultConfig config) {
        String token = null;
        try {
            // Use service account and it's password for Auth.
            token = vault.auth().loginByLDAP(serviceAccountName, Secret.toString(serviceAccountPassword)).getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("Couldn't login into vault", e);
        }
        return new Vault(config.token(token));
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {

        @Override public String getDisplayName() {
            return "Vault LDAP Credentials";
        }

    }
}
