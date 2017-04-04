package com.datapipe.jenkins.vault.configuration;

import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

public class VaultConfiguration extends AbstractDescribableImpl<VaultConfiguration> {
    private String vaultUrl;
    private String vaultTokenCredentialId;

    @DataBoundConstructor
    public VaultConfiguration(String vaultUrl, String vaultTokenCredentialId) {
        this.vaultUrl = vaultUrl;
        this.vaultTokenCredentialId = vaultTokenCredentialId;
    }

    public String getVaultUrl() {
        return vaultUrl;
    }

    public String getVaultTokenCredentialId() {
        return vaultTokenCredentialId;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<VaultConfiguration> {

        @Override
        public String getDisplayName() {
            return "Vault Configuration";
        }
    }
}
