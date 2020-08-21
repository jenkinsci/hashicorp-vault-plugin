package com.datapipe.jenkins.vault.credentials.common;

import com.bettercloud.vault.VaultConfig;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.remoting.Channel;
import hudson.security.ACL;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import jenkins.security.SlaveToMasterCallable;
import org.apache.commons.lang.StringUtils;

public class VaultHelper {

    private static final Logger LOGGER = Logger.getLogger(VaultHelper.class.getName());

    static String getVaultSecret(@NonNull String secretPath, @NonNull String secretKey, @CheckForNull Integer engineVersion) {
        try {
            String secret;
            SecretRetrieve retrieve = new SecretRetrieve(secretPath, secretKey, engineVersion);

            Channel channel = Channel.current();
            if (channel == null) {
                secret = retrieve.call();
            } else {
                secret = channel.call(retrieve);
            }

            return secret;
        } catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    private static class SecretRetrieve extends SlaveToMasterCallable<String, IOException> {

        private static final long serialVersionUID = 1L;

        private final String secretPath;
        private final String secretKey;
        @CheckForNull
        private Integer engineVersion;

        SecretRetrieve(String secretPath, String secretKey, Integer engineVersion) {
            this.secretPath = secretPath;
            this.secretKey = secretKey;
            this.engineVersion = engineVersion;
        }

        @Override
        public String call() throws IOException {
            GlobalVaultConfiguration globalConfig = GlobalVaultConfiguration.get();

            VaultConfiguration configuration = globalConfig.getConfiguration();

            if (configuration == null) {
                throw new IllegalStateException("Vault plugin has not been configured.");
            }

            configuration.fixDefaults();
            if (engineVersion == null) {
                engineVersion = configuration.getEngineVersion();
            }

            String msg = String.format(
                "Retrieving vault secret path=%s key=%s engineVersion=%s",
                secretPath, secretKey, engineVersion);
            LOGGER.info(msg);

            try {
                VaultConfig vaultConfig = configuration.getVaultConfig();

                VaultCredential vaultCredential = configuration.getVaultCredential();
                if (vaultCredential == null) vaultCredential = retrieveVaultCredentials(configuration.getVaultCredentialId());

                VaultAccessor vaultAccessor = new VaultAccessor(vaultConfig, vaultCredential);
                vaultAccessor.setMaxRetries(configuration.getMaxRetries());
                vaultAccessor.setRetryIntervalMilliseconds(configuration.getRetryIntervalMilliseconds());
                vaultAccessor.init();

                Map<String, String> values = vaultAccessor.read(secretPath, engineVersion).getData();

                if (!values.containsKey(secretKey)) {
                    String message = String.format(
                        "Key %s could not be found in path %s",
                        secretKey, secretPath);
                    throw new VaultPluginException(message);
                }

                return values.get(secretKey);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
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
                Jenkins.get(),
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
