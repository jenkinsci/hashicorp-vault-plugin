package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import hudson.Extension;
import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

public class VaultTokenCredentialImpl extends BaseStandardCredentials implements VaultTokenCredential{
    private final @Nonnull Secret secretId;

    private final @Nonnull String roleId;

    @DataBoundConstructor
    public VaultTokenCredentialImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id, @CheckForNull String description, @Nonnull String roleId, @Nonnull Secret secretId) {
        super(scope, id, description);
        this.secretId = secretId;
        this.roleId = roleId;
    }

    @Override
    public String getRoleId() {
        return roleId;
    }

    @Override
    public Secret getSecretId() {
        return secretId;
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override public String getDisplayName() {
            return "Vault Token Credential";
        }

    }
}
