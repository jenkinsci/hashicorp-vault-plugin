package com.datapipe.jenkins.vault.configuration;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import java.io.Serializable;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import static hudson.Util.fixEmptyAndTrim;

public class VaultConfiguration extends AbstractDescribableImpl<VaultConfiguration>
                                implements Serializable {

    private static final int RETRY_INTERVAL_MILLISECONDS = 1000;
    private static final int DEFAULT_TIMEOUT = 30;

    private String vaultUrl;

    private String vaultCredentialId;

    private VaultCredential vaultCredential;

    private Boolean failIfNotFound = DescriptorImpl.DEFAULT_FAIL_NOT_FOUND;

    private Boolean skipSslVerification = DescriptorImpl.DEFAULT_SKIP_SSL_VERIFICATION;

    private Integer engineVersion;

    private String vaultNamespace;

    private String prefixPath;

    private String policies;

    private Boolean disableChildPoliciesOverride;

    private Integer timeout = DEFAULT_TIMEOUT;

    @DataBoundConstructor
    public VaultConfiguration() {
        // no args constructor
    }

    @Deprecated
    public VaultConfiguration(String vaultUrl, String vaultCredentialId, boolean failIfNotFound) {
        setVaultUrl(vaultUrl);
        setVaultCredentialId(vaultCredentialId);
        setFailIfNotFound(failIfNotFound);
    }

    public VaultConfiguration(VaultConfiguration toCopy) {
        this.vaultUrl = toCopy.getVaultUrl();
        this.vaultCredentialId = toCopy.getVaultCredentialId();
        this.vaultCredential = toCopy.getVaultCredential();
        this.failIfNotFound = toCopy.failIfNotFound;
        this.skipSslVerification = toCopy.skipSslVerification;
        this.engineVersion = toCopy.engineVersion;
        this.vaultNamespace = toCopy.vaultNamespace;
        this.prefixPath = toCopy.prefixPath;
        this.policies = toCopy.policies;
        this.disableChildPoliciesOverride = toCopy.disableChildPoliciesOverride;
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
        if (result.vaultCredential == null) {
            result.setVaultCredential(parent.getVaultCredential());
        }
        if (StringUtils.isBlank(result.getVaultUrl())) {
            result.setVaultUrl(parent.getVaultUrl());
        }
        if (result.engineVersion == null) {
            result.setEngineVersion(parent.getEngineVersion());
        }
        if (StringUtils.isBlank(result.getVaultNamespace())) {
            result.setVaultNamespace(parent.getVaultNamespace());
        }
        if (StringUtils.isBlank(result.getPrefixPath())) {
            result.setPrefixPath(parent.getPrefixPath());
        }
        if (StringUtils.isBlank(result.getPolicies()) ||
                (parent.getDisableChildPoliciesOverride() != null && parent.getDisableChildPoliciesOverride())) {
            result.setPolicies(parent.getPolicies());
        }
        if (result.timeout == null) {
            result.setTimeout(parent.getTimeout());
        }
        if (result.failIfNotFound == null) {
            result.setFailIfNotFound(parent.failIfNotFound);
        }
        if (result.skipSslVerification == null) {
            result.setSkipSslVerification(parent.skipSslVerification);
        }
        return result;
    }

    public String getVaultUrl() {
        return vaultUrl;
    }

    public String getVaultCredentialId() {
        return vaultCredentialId;
    }

    public VaultCredential getVaultCredential() {
        return vaultCredential;
    }

    @DataBoundSetter
    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = normalizeUrl(fixEmptyAndTrim(vaultUrl));
    }

    @DataBoundSetter
    public void setVaultCredentialId(String vaultCredentialId) {
        this.vaultCredentialId = fixEmptyAndTrim(vaultCredentialId);
    }

    @DataBoundSetter
    public void setVaultCredential(VaultCredential vaultCredential) {
        this.vaultCredential = vaultCredential;
    }

    public Boolean getFailIfNotFound() {
        return failIfNotFound;
    }

    @DataBoundSetter
    public void setFailIfNotFound(Boolean failIfNotFound) {
        this.failIfNotFound = failIfNotFound;
    }

    public Boolean getSkipSslVerification() {
        return skipSslVerification;
    }

    @DataBoundSetter
    public void setSkipSslVerification(Boolean skipSslVerification) {
        this.skipSslVerification = skipSslVerification;
    }

    public Integer getEngineVersion() {
        return engineVersion;
    }

    @DataBoundSetter
    public void setEngineVersion(Integer engineVersion) {
        this.engineVersion = engineVersion;
    }

    public String getVaultNamespace() {
        return vaultNamespace;
    }

    @DataBoundSetter
    public void setVaultNamespace(String vaultNamespace) {
        this.vaultNamespace = fixEmptyAndTrim(vaultNamespace);
    }

    public String getPrefixPath() {
        return prefixPath;
    }

    @DataBoundSetter
    public void setPrefixPath(String prefixPath) {
        this.prefixPath = fixEmptyAndTrim(prefixPath);
    }

    public String getPolicies() {
        return policies;
    }

    @DataBoundSetter
    public void setPolicies(String policies) {
        this.policies = fixEmptyAndTrim(policies);
    }

    public Boolean getDisableChildPoliciesOverride() {
        return disableChildPoliciesOverride;
    }

    @DataBoundSetter
    public void setDisableChildPoliciesOverride(Boolean disableChildPoliciesOverride) {
        this.disableChildPoliciesOverride = disableChildPoliciesOverride;
    }

    public Integer getTimeout() {
        return timeout;
    }

    @DataBoundSetter
    public void setTimeout(Integer timeout) {
        this.timeout = timeout;
    }

    /**
     * Number of retries when reading a secret from vault
     *
     * @return number of retries
     */
    public int getMaxRetries() {
        final int to = (null != getTimeout()) ? getTimeout() : DEFAULT_TIMEOUT;
        return (int) (to * 1000.0 / RETRY_INTERVAL_MILLISECONDS);
    }

    /**
     * The time in milliseconds in between retries when reading a secret from vault
     *
     * @return 1000 milliseconds
     */
    public int getRetryIntervalMilliseconds() {
        return RETRY_INTERVAL_MILLISECONDS;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<VaultConfiguration> {

        public static final boolean DEFAULT_FAIL_NOT_FOUND = true;

        public static final boolean DEFAULT_SKIP_SSL_VERIFICATION = false;

        public static final int DEFAULT_ENGINE_VERSION = 2;

        @Override
        @NonNull
        public String getDisplayName() {
            return "Vault Configuration";
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillVaultCredentialIdItems(@AncestorInPath Item item,
            @QueryParameter String uri) {
            // This is needed for folders: credentials bound to a folder are
            // realized through domain requirements
            List<DomainRequirement> domainRequirements = URIRequirementBuilder.fromUri(uri).build();
            return new StandardListBoxModel().includeEmptyValue().includeAs(ACL.SYSTEM, item,
                VaultCredential.class, domainRequirements);
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }

    @NonNull
    public VaultConfig getVaultConfig() {
        VaultConfig vaultConfig = new VaultConfig();
        vaultConfig.address(this.getVaultUrl());
        vaultConfig.engineVersion(this.getEngineVersion());
        try {
            vaultConfig.sslConfig(new SslConfig().verify(!this.getSkipSslVerification()).build());

            if (StringUtils.isNotEmpty(this.getVaultNamespace())) {
                vaultConfig.nameSpace(this.getVaultNamespace());
            }

            if (StringUtils.isNotEmpty(this.getPrefixPath())) {
                vaultConfig.prefixPath(this.getPrefixPath());
            }
        } catch (VaultException e) {
            throw new VaultPluginException("Could not set up VaultConfig.", e);
        }
        return vaultConfig;
    }

    public VaultConfiguration fixDefaults() {
        if (getEngineVersion() == null) {
            setEngineVersion(DescriptorImpl.DEFAULT_ENGINE_VERSION);
        }
        if (getSkipSslVerification() == null) {
            setSkipSslVerification(DescriptorImpl.DEFAULT_SKIP_SSL_VERIFICATION);
        }
        if (getFailIfNotFound() == null) {
            setFailIfNotFound(DescriptorImpl.DEFAULT_FAIL_NOT_FOUND);
        }
        return this;
    }

    @Restricted(NoExternalUse.class)
    public static ListBoxModel engineVersions(Item context) {
        ListBoxModel options = new ListBoxModel(
            new Option("2", "2"),
            new Option("1", "1")
        );
        if (context != null) {
            Option option = new Option("Default", "");
            options.add(0, option);
        }
        return options;
    }

    private String normalizeUrl(String url) {
        if (url == null) {
            return null;
        }

        if (url.endsWith("/")) {
            return url.substring(0, url.length() - 1);
        }

        return url;
    }
}
