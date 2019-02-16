package com.datapipe.jenkins.vault.credentials;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

import org.kohsuke.stapler.DataBoundConstructor;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;

import hudson.Extension;
import hudson.util.Secret;

public class VaultAppRoleCredential extends AbstractVaultTokenCredential {
    private final @Nonnull Secret secretId;

    private final @Nonnull String roleId;

    private final String path;

    @DataBoundConstructor
    public VaultAppRoleCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id, @CheckForNull String description, @Nonnull String roleId, @Nonnull Secret secretId, String path) {
        super(scope, id, description);
        this.secretId = secretId;
        this.roleId = roleId;
        if (path == null) {
          this.path = "approle";
        } else {
          this.path = path;
        }
    }

    public String getRoleId() {
        return roleId;
    }

    public Secret getSecretId() {
        return secretId;
    }

    public String getPath() {
        return path;
    }

    @Override
    public String getToken(Vault vault) {
        try {
            return vault.auth().loginByAppRole(path, roleId, Secret.toString(secretId)).getAuthClientToken();
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
