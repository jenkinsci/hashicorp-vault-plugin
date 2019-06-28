package com.datapipe.jenkins.vault.configuration;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import com.datapipe.jenkins.vault.credentials.VaultCredential;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import java.io.Serializable;
import java.util.List;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.ListBoxModel;

public class VaultConfiguration extends AbstractDescribableImpl<VaultConfiguration> implements Serializable {
    private static final int RETRY_INTERVAL_MILLISECONDS = 1000;
    private static final int DEFAULT_TIMEOUT = 30;

    private String vaultUrl;

    private String vaultCredentialId;

    private boolean failIfNotFound = true;

    private boolean skipSslVerification = false;

    private String vaultNamespace;

    private Integer timeout = DEFAULT_TIMEOUT;

    public VaultConfiguration() {
        // no args constructor
    }

    @DataBoundConstructor
    public VaultConfiguration(String vaultUrl, String vaultCredentialId, boolean failIfNotFound, String vaultNamespace, Integer timeout) {
        this.vaultUrl = normalizeUrl(vaultUrl);
        this.vaultCredentialId = vaultCredentialId;
        this.failIfNotFound = failIfNotFound;
        this.vaultNamespace = vaultNamespace;
        this.timeout = (null != timeout) ? timeout : DEFAULT_TIMEOUT;

    }

    public VaultConfiguration(VaultConfiguration toCopy) {
        this.vaultUrl = toCopy.getVaultUrl();
        this.vaultCredentialId = toCopy.getVaultCredentialId();
        this.failIfNotFound = toCopy.failIfNotFound;
        this.vaultNamespace = toCopy.vaultNamespace;
        this.timeout = toCopy.timeout;
    }

    public VaultConfiguration mergeWithParent(VaultConfiguration parent) {
        if (parent == null) {
            return this;
        }
        VaultConfiguration result = new VaultConfiguration(this);
        if (StringUtils.isBlank(result.getVaultCredentialId())) {
            result.setVaultCredentialId(parent.getVaultCredentialId());
        }
        if (StringUtils.isBlank(result.getVaultUrl())) {
            result.setVaultUrl(parent.getVaultUrl());
        }
        if (StringUtils.isBlank(result.getVaultNamespace())) {
            result.setVaultNamespace(parent.getVaultNamespace());
        }
        if (null == result.timeout) {
            result.setTimeout(parent.getTimeout());
        }
        result.failIfNotFound = failIfNotFound;
        return result;
    }

    public String getVaultUrl() {
        return vaultUrl;
    }

    public String getVaultCredentialId() {
        return vaultCredentialId;
    }

    public String getVaultNamespace() {
        return vaultNamespace;
    }

    /**
     * Timeout in seconds for reading a secret from vault
     * @return
     */
    public Integer getTimeout() {
        return this.timeout;
    }

    /**
     * Number of retries when reading a secret from vault
     * @return
     */
    public int getMaxRetries() {
        final Integer to = (null != getTimeout()) ? getTimeout() : DEFAULT_TIMEOUT;
        return (int) (to * 1000.0 / RETRY_INTERVAL_MILLISECONDS);
    }

    /**
     * The time in milliseconds in between retries when reading a secret from vault
     * @return
     */
    public int getRetryIntervalMilliseconds() {
        return RETRY_INTERVAL_MILLISECONDS;
    }



    @DataBoundSetter
    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = normalizeUrl(vaultUrl);
    }

    @DataBoundSetter
    public void setVaultCredentialId(String vaultCredentialId) {
        this.vaultCredentialId = vaultCredentialId;
    }

    @DataBoundSetter
    public void setVaultNamespace(String vaultNamespace) {
        this.vaultNamespace = vaultNamespace;
    }

    public boolean isFailIfNotFound() {
        return failIfNotFound;
    }

    @DataBoundSetter
    public void setFailIfNotFound(boolean failIfNotFound) {
        this.failIfNotFound = failIfNotFound;
    }

    public boolean isSkipSslVerification() {
        return skipSslVerification;
    }

    @DataBoundSetter
    public void setSkipSslVerification(boolean skipSslVerification) {
        this.skipSslVerification = skipSslVerification;
    }

    @DataBoundSetter
    public void setTimeout(Integer timeout) {
        this.timeout = timeout;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<VaultConfiguration> {
        @Override
        public String getDisplayName() {
            return "Vault Configuration";
        }

        public ListBoxModel doFillVaultCredentialIdItems(@AncestorInPath Item item, @QueryParameter String uri) {
            // This is needed for folders: credentials bound to a folder are
            // realized through domain requirements
            List<DomainRequirement> domainRequirements = URIRequirementBuilder.fromUri(uri).build();
            return new StandardListBoxModel().includeEmptyValue().includeAs(ACL.SYSTEM, item,
                    VaultCredential.class, domainRequirements);
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
