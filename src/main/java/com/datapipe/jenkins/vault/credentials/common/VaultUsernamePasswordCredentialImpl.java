package com.datapipe.jenkins.vault.credentials.common;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.cloudbees.plugins.credentials.*;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.VaultBuildWrapper;
import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.security.ACL;
import hudson.util.Secret;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

@SuppressWarnings("ALL")
public class VaultUsernamePasswordCredentialImpl extends BaseStandardCredentials implements VaultUsernamePasswordCredential, StandardUsernamePasswordCredentials {

    public static final String DEFAULT_USERNAME_KEY = "username";
    public static final String DEFAULT_PASSWORD_KEY = "password";
    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = Logger.getLogger(VaultUsernamePasswordCredentialImpl.class.getName());
    private String path;
    private String usernameKey;
    private String passwordKey;
    private Integer engineVersion;

    @DataBoundConstructor
    public VaultUsernamePasswordCredentialImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                                               @CheckForNull String path,
                                               @CheckForNull String usernameKey,
                                               @CheckForNull String passwordKey,
                                               @CheckForNull String engineVersion,
                                               @CheckForNull String description) {
        super(scope, id, description);
        this.path = path;
        this.usernameKey = StringUtils.isEmpty(usernameKey) ? DEFAULT_USERNAME_KEY : usernameKey;
        this.passwordKey = StringUtils.isEmpty(passwordKey) ? DEFAULT_PASSWORD_KEY : passwordKey;
        try {
            this.engineVersion = Integer.valueOf(engineVersion);
        } catch (Exception e) {
            LOGGER.info("Cannot parse engine version number " + engineVersion);
            this.engineVersion = 1;
        }
    }

    @Override
    public String getDisplayName() {
        return this.path;
    }

    @NonNull
    @Override
    public Secret getPassword() {
        return Secret.fromString(getValue(this.passwordKey));
    }

    private String getValue(String valueKey) {
        GlobalVaultConfiguration globalConfig = GlobalConfiguration.all().get(GlobalVaultConfiguration.class);


        ExtensionList<VaultBuildWrapper.DescriptorImpl> extensionList = Jenkins.getInstance().getExtensionList(VaultBuildWrapper.DescriptorImpl.class);
        VaultBuildWrapper.DescriptorImpl descriptor = extensionList.get(0);

        if (descriptor == null) {
            throw new IllegalStateException("Vault plugin has not been configured.");
        }

        try {
            VaultConfig vaultConfig = new VaultConfig()
                    .address(globalConfig.getConfiguration().getVaultUrl())
                    .sslConfig(new SslConfig().verify(globalConfig.getConfiguration().isSkipSslVerification()).build())
                    .nameSpace(globalConfig.getConfiguration().getVaultNamespace());
            VaultCredential vaultCredential = retrieveVaultCredentials(globalConfig.getConfiguration().getVaultCredentialId());

            VaultAccessor vaultAccessor = new VaultAccessor(vaultConfig, vaultCredential);
            vaultAccessor.setMaxRetries(globalConfig.getConfiguration().getMaxRetries());
            vaultAccessor.setRetryIntervalMilliseconds(globalConfig.getConfiguration().getRetryIntervalMilliseconds());
            vaultAccessor.init();

            Map<String, String> values = vaultAccessor.read(this.getPath(), this.getEngineVersion()).getData();

            return values.get(valueKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private VaultCredential retrieveVaultCredentials(String id) {
        if (StringUtils.isBlank(id)) {
            throw new VaultPluginException("The credential id was not configured - please specify the credentials to use.");
        } else {
            LOGGER.log(Level.INFO, "Using credential ID : " + id );
        }
        List<VaultCredential> credentials = CredentialsProvider.lookupCredentials(VaultCredential.class,
                Jenkins.getInstance(),
                ACL.SYSTEM,
                Collections.<DomainRequirement>emptyList());
        VaultCredential credential = CredentialsMatchers.firstOrNull(credentials, new IdMatcher(id));

        if (credential == null) {
            throw new CredentialsUnavailableException(id);
        }

        return credential;
    }

    @NonNull
    @Override
    public String getUsername() {
        return getValue(this.usernameKey);
    }

    @NonNull
    public String getPasswordKey() {
        return passwordKey;
    }

    public void setPasswordKey(String passwordKey) {
        this.passwordKey = passwordKey;
    }

    @NonNull
    public String getUsernameKey() {
        return usernameKey;
    }

    public void setUsernameKey(String usernameKey) {
        this.usernameKey = usernameKey;
    }

    @NonNull
    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public Integer getEngineVersion() {
        return engineVersion;
    }

    public void setEngineVersion(Integer engineVersion) {
        this.engineVersion = engineVersion;
    }

    @Extension
    public static class DescriptorImpl extends CredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault Username-Password Credential";
        }
    }
}
