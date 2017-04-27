package com.datapipe.jenkins.vault.credentials;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

import org.kohsuke.stapler.DataBoundConstructor;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.datapipe.jenkins.vault.exception.VaultPluginException;

import hudson.Extension;
import hudson.util.Secret;

public class VaultAppRoleCredential extends BaseStandardCredentials implements VaultCredential {
    private final @Nonnull Secret secretId;

    private final @Nonnull String roleId;

    @DataBoundConstructor
    public VaultAppRoleCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id, @CheckForNull String description, @Nonnull String roleId, @Nonnull Secret secretId) {
        super(scope, id, description);
        this.secretId = secretId;
        this.roleId = roleId;
    }

    public String getRoleId() {
        return roleId;
    }

    public Secret getSecretId() {
        return secretId;
    }

    @Override
    public Vault authorizeWithVault(Vault vault, VaultConfig config) {
        String token = null;
        try {
            token = vault.auth().loginByAppRole("approle", roleId, Secret.toString(secretId)).getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault", e);
        }
        return new Vault(config.token(token));
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override public String getDisplayName() {
            return "Vault App Role Credential";
        }

    }
}
