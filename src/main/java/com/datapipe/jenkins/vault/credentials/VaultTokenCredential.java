package com.datapipe.jenkins.vault.credentials;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

import com.bettercloud.vault.Vault;
import org.kohsuke.stapler.DataBoundConstructor;

import com.cloudbees.plugins.credentials.CredentialsScope;

import hudson.Extension;
import hudson.util.Secret;

public class VaultTokenCredential extends AbstractVaultTokenCredential {
    private Secret token;

    @DataBoundConstructor
    public VaultTokenCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id, @CheckForNull String description, @Nonnull Secret token) {
        super(scope, id, description);
        this.token = token;
    }


    @Override
    public String getToken(Vault vault) {
        return Secret.toString(token);
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override public String getDisplayName() {
            return "Vault Token Credential";
        }

    }
}
