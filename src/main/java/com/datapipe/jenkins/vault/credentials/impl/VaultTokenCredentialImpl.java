package com.datapipe.jenkins.vault.credentials.impl;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import hudson.Extension;
import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

public class VaultTokenCredentialImpl extends BaseStandardCredentials implements VaultTokenCredential{
    private final @Nonnull Secret token;

    @DataBoundConstructor
    public VaultTokenCredentialImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id, @CheckForNull String description, @Nonnull Secret token) {
        super(scope, id, description);
        this.token = token;
    }

    @Override
    public Secret getToken() {
        return token;
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override public String getDisplayName() {
            return "Vault Token Credential";
        }

    }
}
