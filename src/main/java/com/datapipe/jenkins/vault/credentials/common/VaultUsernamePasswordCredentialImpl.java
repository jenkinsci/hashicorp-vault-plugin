package com.datapipe.jenkins.vault.credentials.common;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.VaultConfig;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.VaultBuildWrapper;
import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

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

    private static String getVaultSecret(String secretPath, String secretKey,
        Integer engineVersion) {
        if (Jenkins.getInstanceOrNull() == null) {
            LOGGER.warning("Cannot retrieve secret becuase Jenkins.instance is not available");
            return null;
        }

        LOGGER.info(
            "Retrieving vault secret path=" + secretPath + " key=" + secretKey + " engineVersion="
                + engineVersion);

        GlobalVaultConfiguration globalConfig = GlobalConfiguration.all()
            .get(GlobalVaultConfiguration.class);

        ExtensionList<VaultBuildWrapper.DescriptorImpl> extensionList = Jenkins.getInstance()
            .getExtensionList(VaultBuildWrapper.DescriptorImpl.class);
        VaultBuildWrapper.DescriptorImpl descriptor = extensionList.get(0);

        if (descriptor == null) {
            throw new IllegalStateException("Vault plugin has not been configured.");
        }

        try {
            VaultConfig vaultConfig = new VaultConfig()
                .address(globalConfig.getConfiguration().getVaultUrl())
                .sslConfig(
                    new SslConfig().verify(globalConfig.getConfiguration().isSkipSslVerification())
                        .build())
                .engineVersion(engineVersion);

            if (StringUtils.isNotEmpty(globalConfig.getConfiguration().getVaultNamespace())) {
                vaultConfig.nameSpace(globalConfig.getConfiguration().getVaultNamespace());
            }

            if (StringUtils.isNotEmpty(globalConfig.getConfiguration().getPrefixPath())) {
                vaultConfig.prefixPath(globalConfig.getConfiguration().getPrefixPath());
            }

            VaultCredential vaultCredential = retrieveVaultCredentials(
                globalConfig.getConfiguration().getVaultCredentialId());

            VaultAccessor vaultAccessor = new VaultAccessor(vaultConfig, vaultCredential);
            vaultAccessor.setMaxRetries(globalConfig.getConfiguration().getMaxRetries());
            vaultAccessor.setRetryIntervalMilliseconds(
                globalConfig.getConfiguration().getRetryIntervalMilliseconds());
            vaultAccessor.init();

            Map<String, String> values = vaultAccessor.read(secretPath, engineVersion).getData();

            if (!values.containsKey(secretKey)) {
                throw new VaultPluginException(
                    "Key " + secretKey + " could not be found in path " + secretPath);
            }

            return values.get(secretKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static VaultCredential retrieveVaultCredentials(String id) {
        if (StringUtils.isBlank(id)) {
            throw new VaultPluginException(
                "The credential id was not configured - please specify the credentials to use.");
        } else {
            LOGGER.log(Level.INFO, "Retrieving vault credential ID : " + id);
        }
        List<VaultCredential> credentials = CredentialsProvider
            .lookupCredentials(VaultCredential.class,
                Jenkins.getInstance(),
                ACL.SYSTEM,
                Collections.<DomainRequirement>emptyList());
        VaultCredential credential = CredentialsMatchers
            .firstOrNull(credentials, new IdMatcher(id));

        if (credential == null) {
            throw new CredentialsUnavailableException(id);
        }

        return credential;
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
