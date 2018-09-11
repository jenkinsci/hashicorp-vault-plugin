package com.datapipe.jenkins.vault.credentials;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import org.kohsuke.stapler.DataBoundConstructor;


import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;

import hudson.Extension;
import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundSetter;

public class VaultGithubTokenCredential extends AbstractVaultTokenCredential {

    // https://www.vaultproject.io/docs/auth/github.html#generate-a-github-personal-access-token
    private final @Nonnull Secret accessToken;

    private String vaultUrl;

    @DataBoundConstructor
    public VaultGithubTokenCredential(@CheckForNull CredentialsScope scope,
                                      @CheckForNull String id,
                                      @CheckForNull String description,
                                      @Nonnull Secret accessToken) {
        super(scope, id, description);
        this.accessToken = accessToken;
    }

    @DataBoundSetter
    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = vaultUrl;
    }

    public Secret getAccessToken() {
        return accessToken;
    }

    public String getToken() {
        try {
            VaultConfig config = new VaultConfig(this.vaultUrl).build();
            return new Vault(config).auth().loginByGithub(Secret.toString(accessToken)).getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault", e);
        }
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @Override
        public String getDisplayName() {
            return "Vault Github Token Credential";
        }
    }
}
