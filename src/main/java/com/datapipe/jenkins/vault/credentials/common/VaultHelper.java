package com.datapipe.jenkins.vault.credentials.common;

import com.bettercloud.vault.VaultConfig;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.configuration.VaultConfigResolver;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionList;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;

public class VaultHelper {

    private static final Logger LOGGER = Logger.getLogger(VaultHelper.class.getName());

    static Map<String, String> getVaultSecret(@NonNull String secretPath,
                                              @CheckForNull String prefixPath,
                                              @CheckForNull String namespace,
                                              @CheckForNull Integer engineVersion) {
        VaultConfiguration configuration = null;
        ItemGroup jenkins = Jenkins.get();

        for (VaultConfigResolver resolver : ExtensionList.lookup(VaultConfigResolver.class)) {
            if (configuration != null) {
                configuration = configuration
                    .mergeWithParent(resolver.getVaultConfig(jenkins));
            } else {
                configuration = resolver.getVaultConfig(jenkins);
            }
        }

        if (configuration == null) {
            throw new IllegalStateException("Vault plugin has not been configured.");
        }

        configuration.fixDefaults();
        if (engineVersion == null) {
            engineVersion = configuration.getEngineVersion();
        }

        String msg = String.format(
            "Retrieving vault secret path=%s engineVersion=%s",
            secretPath, engineVersion);
        LOGGER.info(msg);

        try {
            VaultConfig vaultConfig = configuration.getVaultConfig();

            if (prefixPath != null) {
                vaultConfig.prefixPath(prefixPath);
            }

            if (namespace != null) {
                vaultConfig.nameSpace(namespace);
            }

            VaultCredential vaultCredential = configuration.getVaultCredential();
            if (vaultCredential == null)
                vaultCredential = retrieveVaultCredentials(
                    configuration.getVaultCredentialId());

            VaultAccessor vaultAccessor = new VaultAccessor(vaultConfig, vaultCredential);
            vaultAccessor.setMaxRetries(configuration.getMaxRetries());
            vaultAccessor.setRetryIntervalMilliseconds(
                configuration.getRetryIntervalMilliseconds());
            vaultAccessor.init();

            return vaultAccessor.read(secretPath, engineVersion).getData();
        } catch (VaultPluginException vpe) {
            throw vpe;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static String getVaultSecretKey(@NonNull String secretPath,
                                    @NonNull String secretKey,
                                    @CheckForNull String prefixPath,
                                    @CheckForNull String namespace,
                                    @CheckForNull Integer engineVersion) {
        try {
            Map<String, String> values = getVaultSecret(secretPath, prefixPath, namespace, engineVersion);

            if (!values.containsKey(secretKey)) {
                String message = String.format(
                    "Key %s could not be found in path %s",
                    secretKey, secretPath);
                throw new VaultPluginException(message);
            }

            return values.get(secretKey);
        } catch (IllegalStateException e) {
            throw new IllegalStateException(e);
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
                Jenkins.getInstanceOrNull(),
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
