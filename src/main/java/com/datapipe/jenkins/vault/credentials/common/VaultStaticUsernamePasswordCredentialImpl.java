package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecretKey;
import static org.apache.commons.lang.StringUtils.defaultIfBlank;

@SuppressWarnings("ALL")
public class VaultStaticUsernamePasswordCredentialImpl extends AbstractVaultBaseStandardCredentials
    implements VaultStaticUsernamePasswordCredential {

    public static final String DEFAULT_PASSWORD_KEY = "password";

    private static final long serialVersionUID = 1L;

    private String username;
    private String passwordKey;

    @DataBoundConstructor
    public VaultStaticUsernamePasswordCredentialImpl(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
    }

    @NonNull
    public String getUsername() {
        return username == null ? "" : username;
    }

    @DataBoundSetter
    public void setUsername(String username) {
        this.username = username;
    }

    @NonNull
    public String getPasswordKey() {
        return passwordKey;
    }

    @DataBoundSetter
    public void setPasswordKey(String passwordKey) {
        this.passwordKey = defaultIfBlank(passwordKey, DEFAULT_PASSWORD_KEY);
    }

    @NonNull
    @Override
    public Secret getPassword() {
        String secretKey = defaultIfBlank(passwordKey, DEFAULT_PASSWORD_KEY);
        String secret = getVaultSecretKeyValue(secretKey);
        return Secret.fromString(secret);
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault Username-Password Credential (Static Username)";
        }

        public FormValidation doTestConnection(
            @AncestorInPath ItemGroup<Item> context,
            @QueryParameter("path") String path,
            @QueryParameter("passwordKey") String passwordKey,
            @QueryParameter("prefixPath") String prefixPath,
            @QueryParameter("namespace") String namespace,
            @QueryParameter("engineVersion") Integer engineVersion) {

            Jenkins.get().checkPermission(Jenkins.ADMINISTER);

            try {
                getVaultSecretKey(path, defaultIfBlank(passwordKey, DEFAULT_PASSWORD_KEY),
                    prefixPath, namespace, engineVersion, context);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve password key: \n" + e);
            }

            return FormValidation.ok("Successfully retrieved the password from Vault");
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }

    static class SelfContained extends VaultStaticUsernamePasswordCredentialImpl {
        private final String resolvedUsername;
        private final Secret password;

        public SelfContained(VaultStaticUsernamePasswordCredentialImpl base) {
            super(base.getScope(), base.getId(), base.getDescription());
            resolvedUsername = base.getUsername();
            password = base.getPassword();
        }

        @NonNull
        @Override
        public String getUsername() {
            return resolvedUsername;
        }

        @NonNull
        @Override
        public Secret getPassword() {
            return password;
        }
    }

    @Extension
    public static class SnapshotTaker
        extends CredentialsSnapshotTaker<VaultStaticUsernamePasswordCredentialImpl> {

        @Override
        public Class<VaultStaticUsernamePasswordCredentialImpl> type() {
            return VaultStaticUsernamePasswordCredentialImpl.class;
        }

        @Override
        public VaultStaticUsernamePasswordCredentialImpl snapshot(
            VaultStaticUsernamePasswordCredentialImpl credentials) {
            return new SelfContained(credentials);
        }
    }
}
