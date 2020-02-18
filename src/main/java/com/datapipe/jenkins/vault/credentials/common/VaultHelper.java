package com.datapipe.jenkins.vault.credentials.common;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.VaultConfig;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.VaultBuildWrapper;
import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import hudson.ExtensionList;
import hudson.security.ACL;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;

public class VaultHelper {
    private static final Logger LOGGER = Logger.getLogger(VaultHelper.class.getName());

    static String getVaultSecret(@Nonnull String secretPath, @Nonnull String secretKey, @Nonnull Integer engineVersion) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            LOGGER.warning("Cannot retrieve secret becuase Jenkins.instance is not available");
            return null;
        }

        LOGGER.info(
            "Retrieving vault secret path=" + secretPath + " key=" + secretKey + " engineVersion="
                + engineVersion);

        GlobalVaultConfiguration globalConfig = GlobalConfiguration.all()
            .get(GlobalVaultConfiguration.class);

        if (globalConfig == null) {
            throw new IllegalStateException("Vault plugin has not been configured.");
        }

        ExtensionList<VaultBuildWrapper.DescriptorImpl> extensionList = jenkins
            .getExtensionList(VaultBuildWrapper.DescriptorImpl.class);
        VaultBuildWrapper.DescriptorImpl descriptor = extensionList.get(0);

        VaultConfiguration configuration = globalConfig.getConfiguration();

        if (descriptor == null || configuration == null) {
            throw new IllegalStateException("Vault plugin has not been configured.");
        }

        try {
            SslConfig sslConfig = new SslConfig()
                .verify(configuration.isSkipSslVerification())
                .build();

            VaultConfig vaultConfig = new VaultConfig()
                .address(configuration.getVaultUrl())
                .sslConfig(sslConfig)
                .engineVersion(engineVersion);

            if (StringUtils.isNotEmpty(configuration.getVaultNamespace())) {
                vaultConfig.nameSpace(configuration.getVaultNamespace());
            }

            if (StringUtils.isNotEmpty(configuration.getPrefixPath())) {
                vaultConfig.prefixPath(configuration.getPrefixPath());
            }

            VaultCredential vaultCredential = retrieveVaultCredentials(
                configuration.getVaultCredentialId());

            VaultAccessor vaultAccessor = new VaultAccessor(vaultConfig, vaultCredential);
            vaultAccessor.setMaxRetries(configuration.getMaxRetries());
            vaultAccessor.setRetryIntervalMilliseconds(
                configuration.getRetryIntervalMilliseconds());
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
}
