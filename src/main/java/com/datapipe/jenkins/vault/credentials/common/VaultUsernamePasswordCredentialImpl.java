package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
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

@SuppressWarnings("ALL")
public class VaultUsernamePasswordCredentialImpl extends BaseStandardCredentials implements
    VaultUsernamePasswordCredential {

    public static final String DEFAULT_USERNAME_KEY = "username";
    public static final String DEFAULT_PASSWORD_KEY = "password";
    public static final Integer DEFAULT_ENGINE_VERSION = 2;

    private static final long serialVersionUID = 1L;

    private String path;
    private String usernameKey;
    private String passwordKey;
    private Integer engineVersion;

    @DataBoundConstructor
    public VaultUsernamePasswordCredentialImpl(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
        setEngineVersion(DEFAULT_ENGINE_VERSION);
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
    public String getUsername() {
        String secretKey = defaultIfBlank(usernameKey, DEFAULT_USERNAME_KEY);
        return getVaultSecret(path, secretKey, engineVersion);
    }

    @NonNull
    @Override
    public Secret getPassword() {
        String secretKey = defaultIfBlank(passwordKey, DEFAULT_PASSWORD_KEY);
        String secret = getVaultSecret(path, secretKey, engineVersion);
        return Secret.fromString(secret);
    }

    @Extension(ordinal = 1)
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault Username-Password Credential";
        }

        public FormValidation doTestConnection(
            @QueryParameter("path") String path,
            @QueryParameter("usernameKey") String usernameKey,
            @QueryParameter("passwordKey") String passwordKey,
            @QueryParameter("engineVersion") Integer engineVersion) {

            String username = null;
            try {
                username = getVaultSecret(path, defaultIfBlank(usernameKey, DEFAULT_USERNAME_KEY), engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve username key: \n" + e);
            }

            try {
                getVaultSecret(path, defaultIfBlank(passwordKey, DEFAULT_PASSWORD_KEY), engineVersion);
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
