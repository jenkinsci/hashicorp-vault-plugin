package com.datapipe.jenkins.vault.configuration;

import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.ListBoxModel;

public class VaultConfiguration extends AbstractDescribableImpl<VaultConfiguration> {
    private String vaultUrl;

    private String vaultTokenCredentialId;

    public VaultConfiguration() {
        // no args constructor
    }

    @DataBoundConstructor
    public VaultConfiguration(String vaultUrl, String vaultTokenCredentialId) {
        this.vaultUrl = normalizeUrl(vaultUrl);
        this.vaultTokenCredentialId = vaultTokenCredentialId;
    }

    public VaultConfiguration(VaultConfiguration toCopy) {
        this.vaultUrl = toCopy.getVaultUrl();
        this.vaultTokenCredentialId = toCopy.getVaultTokenCredentialId();
    }

    public VaultConfiguration mergeWithParent(VaultConfiguration parent) {
        if (parent == null) {
            return this;
        }
        VaultConfiguration result = new VaultConfiguration(this);
        if (StringUtils.isBlank(result.getVaultTokenCredentialId())) {
            result.setVaultTokenCredentialId(parent.getVaultTokenCredentialId());
        }
        if (StringUtils.isBlank(result.getVaultUrl())) {
            result.setVaultUrl(parent.getVaultUrl());
        }
        return result;
    }

    public String getVaultUrl() {
        return vaultUrl;
    }

    public String getVaultTokenCredentialId() {
        return vaultTokenCredentialId;
    }

    @DataBoundSetter
    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = normalizeUrl(vaultUrl);
    }

    @DataBoundSetter
    public void setVaultTokenCredentialId(String vaultTokenCredentialId) {
        this.vaultTokenCredentialId = vaultTokenCredentialId;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<VaultConfiguration> {
        @Override
        public String getDisplayName() {
            return "Vault Configuration";
        }

        public ListBoxModel doFillVaultTokenCredentialIdItems(@AncestorInPath Item item, @QueryParameter String uri) {
            // This is needed for folders: credentials bound to a folder are
            // realized through domain requirements
            List<DomainRequirement> domainRequirements = URIRequirementBuilder.fromUri(uri).build();
            return new StandardListBoxModel().includeEmptyValue().includeAs(ACL.SYSTEM, item,
                    VaultTokenCredential.class, domainRequirements);
        }
    }

    private String normalizeUrl(String url) {
        if(url == null) {
            return null;
        }

        if (url.endsWith("/")) {
            return url.substring(0, url.length() - 1);
        }

        return url;
    }
}
