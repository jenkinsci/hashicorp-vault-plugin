package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import java.util.function.Supplier;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecretKey;
import static org.apache.commons.lang.StringUtils.defaultIfBlank;

public class VaultStringCredentialImpl extends AbstractVaultBaseStandardCredentials implements VaultStringCredential {

    public static final String DEFAULT_VAULT_KEY = "secret";

    private static final long serialVersionUID = 1L;
    private Supplier<Secret> value;

    private String vaultKey;

    public VaultStringCredentialImpl(CredentialsScope scope, String id, String description, Supplier<Secret> valueSupplier) {
        super(scope, id, description);
        value = valueSupplier;
    }

    @DataBoundConstructor
    public VaultStringCredentialImpl(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
        value = null;
    }

    @NonNull
    public String getVaultKey() {
        return vaultKey;
    }

    @DataBoundSetter
    public void setVaultKey(String vaultKey) {
        this.vaultKey = defaultIfBlank(vaultKey, DEFAULT_VAULT_KEY);
    }

    @NonNull
    @Override
    public Secret getSecret() {
        if (value != null) {
            return value.get();
        }
        return Secret.fromString(getVaultSecretKeyValue(getVaultKey()));
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault Secret Text Credential";
        }

        public FormValidation doTestConnection(
            @AncestorInPath ItemGroup<Item> context,
            @QueryParameter("path") String path,
            @QueryParameter("vaultKey") String vaultKey,
            @QueryParameter("prefixPath") String prefixPath,
            @QueryParameter("namespace") String namespace,
            @QueryParameter("engineVersion") Integer engineVersion) {

            try {
                getVaultSecretKey(path, defaultIfBlank(vaultKey, DEFAULT_VAULT_KEY), prefixPath, namespace, engineVersion);
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
