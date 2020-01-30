package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.util.logging.Logger;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecret;

@SuppressWarnings("ALL")
public class VaultUsernamePasswordCredentialImpl extends BaseStandardCredentials implements
    VaultUsernamePasswordCredential {

    public static final String DEFAULT_USERNAME_KEY = "username";
    public static final String DEFAULT_PASSWORD_KEY = "password";
    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = Logger
        .getLogger(VaultUsernamePasswordCredentialImpl.class.getName());
    private String path;
    private String usernameKey;
    private String passwordKey;
    private Integer engineVersion;

    @DataBoundConstructor
    public VaultUsernamePasswordCredentialImpl(CredentialsScope scope, String id,
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
    public String getUsernameKey() {
        return usernameKey;
    }

    @DataBoundSetter
    public void setUsernameKey(String usernameKey) {
        this.usernameKey = StringUtils.isEmpty(usernameKey) ? DEFAULT_USERNAME_KEY : usernameKey;
    }

    @NonNull
    public String getPasswordKey() {
        return passwordKey;
    }

    @DataBoundSetter
    public void setPasswordKey(String passwordKey) {
        this.passwordKey = StringUtils.isEmpty(passwordKey) ? DEFAULT_PASSWORD_KEY : passwordKey;
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
        return getValue(this.usernameKey);
    }

    @NonNull
    @Override
    public Secret getPassword() {
        return Secret.fromString(getValue(this.passwordKey));
    }


    private String getValue(String valueKey) {
        return getVaultSecret(this.getPath(), valueKey, this.getEngineVersion());
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
                username = getVaultSecret(path, usernameKey, engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve username key: \n" + e);
            }

            try {
                getVaultSecret(path, passwordKey, engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve password key: \n" + e);
            }

            return FormValidation
                .ok("Successfully retrieved username " + username + " and the password");
        }

    }
}
