package com.datapipe.jenkins.vault.credentials;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

import com.bettercloud.vault.VaultConfig;
import org.kohsuke.stapler.DataBoundConstructor;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;

import hudson.Extension;
import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundSetter;

public class VaultAppRoleCredential extends AbstractVaultTokenCredential {
    private final @Nonnull Secret secretId;

    private final @Nonnull String roleId;

    private String vaultUrl;

    @DataBoundConstructor
    public VaultAppRoleCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id, @CheckForNull String description, @Nonnull String roleId, @Nonnull Secret secretId) {
        super(scope, id, description);
        this.secretId = secretId;
        this.roleId = roleId;
    }

    @DataBoundSetter
    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = vaultUrl;
    }

    public String getRoleId() {
        return roleId;
    }

    public Secret getSecretId() {
        return secretId;
    }

    public String getToken() {
        try {
            VaultConfig config = new VaultConfig(this.vaultUrl).build();
            return new Vault(config).auth().loginByAppRole("approle", roleId, Secret.toString(secretId)).getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault", e);
        }
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override public String getDisplayName() {
            return "Vault App Role Credential";
        }

    }
}
