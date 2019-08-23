package com.datapipe.jenkins.vault.configuration;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
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

public class VaultConfiguration
    extends AbstractDescribableImpl<VaultConfiguration>
    implements Serializable {

    private String vaultUrl;

    private String vaultCACert;

    private String vaultCredentialId;

    private boolean failIfNotFound = DescriptorImpl.DEFAULT_FAIL_NOT_FOUND;

    private boolean skipSslVerification = DescriptorImpl.DEFAULT_SKIP_SSL_VERIFICATION;

    private Integer engineVersion;

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
        this.vaultCACert = toCopy.getVaultCACert();
        this.vaultCredentialId = toCopy.getVaultCredentialId();
        this.failIfNotFound = toCopy.failIfNotFound;
        this.skipSslVerification = toCopy.skipSslVerification;
        this.engineVersion = toCopy.engineVersion;
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
        if (StringUtils.isBlank(result.getVaultCACert())) {
            result.setVaultCACert(parent.getVaultCACert());
        }
        if (result.engineVersion == null) {
            result.engineVersion = parent.getEngineVersion();
        }
        result.failIfNotFound = failIfNotFound;
        return result;
    }

    public String getVaultUrl() {
        return vaultUrl;
    }

    public String getVaultCACert() { return vaultCACert; }

    public String getVaultCredentialId() {
        return vaultCredentialId;
    }

    @DataBoundSetter
    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = normalizeUrl(fixEmptyAndTrim(vaultUrl));
    }

    @DataBoundSetter
    public void setVaultCACert(String vaultCACert) { this.vaultCACert = vaultCACert; }

    @DataBoundSetter
    public void setVaultCredentialId(String vaultCredentialId) {
        this.vaultCredentialId = fixEmptyAndTrim(vaultCredentialId);
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

    public Integer getEngineVersion() {
        return engineVersion;
    }

    @DataBoundSetter
    public void setEngineVersion(Integer engineVersion) {
        this.engineVersion = engineVersion;
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
