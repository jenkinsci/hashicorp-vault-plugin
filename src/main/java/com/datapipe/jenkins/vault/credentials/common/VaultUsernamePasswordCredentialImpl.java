package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
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
public class VaultUsernamePasswordCredentialImpl extends AbstractVaultBaseStandardCredentials implements
    VaultUsernamePasswordCredential {

    public static final String DEFAULT_USERNAME_KEY = "username";
    public static final String DEFAULT_PASSWORD_KEY = "password";

    private static final long serialVersionUID = 1L;

    private String usernameKey;
    private String passwordKey;

    @DataBoundConstructor
    public VaultUsernamePasswordCredentialImpl(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
    }

    @NonNull
    public String getUsernameKey() {
        return usernameKey;
    }

    @DataBoundSetter
    public void setUsernameKey(String usernameKey) {
        this.usernameKey = defaultIfBlank(usernameKey, DEFAULT_USERNAME_KEY);
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
    public String getUsername() {
        String secretKey = defaultIfBlank(usernameKey, DEFAULT_USERNAME_KEY);
        return getVaultSecretKeyValue(secretKey);
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
            return "Vault Username-Password Credential";
        }

        public FormValidation doTestConnection(
            @AncestorInPath ItemGroup<Item> context,
            @QueryParameter("path") String path,
            @QueryParameter("usernameKey") String usernameKey,
            @QueryParameter("passwordKey") String passwordKey,
            @QueryParameter("prefixPath") String prefixPath,
            @QueryParameter("namespace") String namespace,
            @QueryParameter("engineVersion") Integer engineVersion) {

            Jenkins.get().checkPermission(Jenkins.ADMINISTER);

            String username = null;
            try {
                username = getVaultSecretKey(path, defaultIfBlank(usernameKey, DEFAULT_USERNAME_KEY), prefixPath, namespace, engineVersion, context);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve username key: \n" + e);
            }

            try {
                getVaultSecretKey(path, defaultIfBlank(passwordKey, DEFAULT_PASSWORD_KEY), prefixPath, namespace, engineVersion, context);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve password key: \n" + e);
            }

            return FormValidation
                .ok("Successfully retrieved username " + username + " and the password");
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }
}
