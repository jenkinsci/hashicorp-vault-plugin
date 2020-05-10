package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecret;
import static org.apache.commons.lang.StringUtils.defaultIfBlank;

public class VaultStringCredentialImpl extends BaseStandardCredentials implements VaultStringCredential {

    public static final String DEFAULT_VAULT_KEY = "secret";

    private static final long serialVersionUID = 1L;

    private String path;
    private String vaultKey;
    private Integer engineVersion;

    @DataBoundConstructor
    public VaultStringCredentialImpl(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
    }

    @NonNull
    public String getPath() {
        return path;
    }

    @DataBoundSetter
    public void setPath(String path) {
        this.path = path;
    }

    @NonNull
    public String getVaultKey() {
        return vaultKey;
    }

    @DataBoundSetter
    public void setVaultKey(String vaultKey) {
        this.vaultKey = defaultIfBlank(vaultKey, DEFAULT_VAULT_KEY);
    }

    public Integer getEngineVersion() {
        return engineVersion;
    }

    @DataBoundSetter
    public void setEngineVersion(Integer engineVersion) {
        this.engineVersion = engineVersion;
    }

    @Override
    public String getDisplayName() {
        return this.path;
    }

    @NonNull
    @Override
    public Secret getSecret() {
        String k = defaultIfBlank(vaultKey, DEFAULT_VAULT_KEY);
        String s = getVaultSecret(path, k, engineVersion);
        if (s == null) {
            throw new VaultPluginException("Fetching from Vault failed for key " + k, null);
        }
        return Secret.fromString(s);
    }

    @Extension(ordinal = 1)
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault Secret Text Credential";
        }

        public FormValidation doTestConnection(
            @QueryParameter("path") String path,
            @QueryParameter("vaultKey") String vaultKey,
            @QueryParameter("engineVersion") Integer engineVersion) {

            try {
                getVaultSecret(path, defaultIfBlank(vaultKey, DEFAULT_VAULT_KEY), engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve Vault secret: \n" + e);
            }

            return FormValidation
                .ok("Successfully retrieved secret by key " + vaultKey);
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }
}
