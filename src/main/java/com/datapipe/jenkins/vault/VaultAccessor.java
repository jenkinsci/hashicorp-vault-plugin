package com.datapipe.jenkins.vault;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;
import com.datapipe.jenkins.vault.configuration.VaultConfigResolver;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import com.datapipe.jenkins.vault.model.VaultSecret;
import com.datapipe.jenkins.vault.model.VaultSecretValue;
import hudson.EnvVars;
import hudson.ExtensionList;
import hudson.Util;
import hudson.model.Run;
import hudson.security.ACL;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.json.Json;
import io.github.jopenlibs.vault.json.JsonArray;
import io.github.jopenlibs.vault.json.JsonValue;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.response.VaultResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import java.io.PrintStream;
import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.text.StringSubstitutor;

public class VaultAccessor implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private VaultConfig config;
    private VaultCredential credential;
    private List<String> policies;
    private int maxRetries = 0;
    private int retryIntervalMilliseconds = 1000;

    private transient Vault vault;

    public VaultAccessor() {
        this.config = new VaultConfig();
    }

    public VaultAccessor(VaultConfig config, VaultCredential credential) {
        this.config = config;
        this.credential = credential;
    }

    public VaultAccessor init() {
        try {
            config.build();

            if (credential == null) {
                vault = Vault.create(config);
            } else {
                vault = credential.authorizeWithVault(config, policies);
            }

            vault.withRetries(maxRetries, retryIntervalMilliseconds);
        } catch (VaultException e) {
            throw new VaultPluginException("failed to connect to vault", e);
        }
        return this;
    }

    public VaultConfig getConfig() {
        return config;
    }

    public void setConfig(VaultConfig config) {
        this.config = config;
    }

    public VaultCredential getCredential() {
        return credential;
    }

    public void setCredential(VaultCredential credential) {
        this.credential = credential;
    }

    public List<String> getPolicies() {
        return policies;
    }

    public void setPolicies(List<String> policies) {
        this.policies = policies;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(int maxRetries) {
        this.maxRetries = maxRetries;
    }

    public int getRetryIntervalMilliseconds() {
        return retryIntervalMilliseconds;
    }

    public void setRetryIntervalMilliseconds(int retryIntervalMilliseconds) {
        this.retryIntervalMilliseconds = retryIntervalMilliseconds;
    }

    @Deprecated
    public void init(String url, VaultCredential credential) {
        config.address(url);
        this.credential = credential;
    }

    public LogicalResponse read(String path, Integer engineVersion) {
        try {
            this.config.engineVersion(engineVersion);
            return vault.logical().read(path);
        } catch (VaultException e) {
            throw new VaultPluginException(
                "could not read from vault: " + e.getMessage() + " at path: " + path, e);
        }
    }

    public VaultResponse revoke(String leaseId) {
        try {
            return vault.leases().revoke(leaseId);
        } catch (VaultException e) {
            throw new VaultPluginException(
                "could not revoke vault lease (" + leaseId + "):" + e.getMessage());
        }
    }

    private static StringSubstitutor getPolicyTokenSubstitutor(EnvVars envVars) {
        String jobName = envVars.get("JOB_NAME");
        String jobBaseName = envVars.get("JOB_BASE_NAME");
        String folder = "";
        if (!jobName.equals(jobBaseName) && jobName.contains("/")) {
            String[] jobElements = jobName.split("/");
            folder = Arrays.stream(jobElements)
                .limit(jobElements.length - 1)
                .collect(Collectors.joining("/"));
        }
        Map<String, String> valueMap = new HashMap<>();
        valueMap.put("job_base_name", jobBaseName);
        valueMap.put("job_name", jobName);
        valueMap.put("job_name_us", jobName.replaceAll("/", "_"));
        valueMap.put("job_folder", folder);
        valueMap.put("job_folder_us", folder.replaceAll("/", "_"));
        valueMap.put("node_name", envVars.get("NODE_NAME"));
        return new StringSubstitutor(valueMap);
    }

    protected static List<String> generatePolicies(String policies, EnvVars envVars) {
        if (StringUtils.isBlank(policies)) {
            return null;
        }
        return Arrays.stream(getPolicyTokenSubstitutor(envVars).replace(policies).split("\n"))
            .filter(StringUtils::isNotBlank)
            .map(String::trim)
            .collect(Collectors.toList());
    }

    public static Map<String, String> retrieveVaultSecrets(Run<?,?> run, PrintStream logger, EnvVars envVars, VaultAccessor vaultAccessor, VaultConfiguration initialConfiguration, List<VaultSecret> vaultSecrets) {
        Map<String, String> overrides = new HashMap<>();

        VaultConfiguration config = pullAndMergeConfiguration(run, initialConfiguration);
        String url = config.getVaultUrl();

        if (StringUtils.isBlank(url)) {
            throw new VaultPluginException(
                "The vault url was not configured - please specify the vault url to use.");
        }

        VaultConfig vaultConfig = config.getVaultConfig();
        VaultCredential credential = config.getVaultCredential();
        if (credential == null) {
            credential = retrieveVaultCredentials(run, config);
        }

        String prefixPath = StringUtils.isBlank(config.getPrefixPath())
            ? ""
            : Util.ensureEndsWith(envVars.expand(config.getPrefixPath()), "/");

        if (vaultAccessor == null) {
            vaultAccessor = new VaultAccessor();
        }
        vaultAccessor.setConfig(vaultConfig);
        vaultAccessor.setCredential(credential);
        vaultAccessor.setPolicies(generatePolicies(config.getPolicies(), envVars));
        vaultAccessor.setMaxRetries(config.getMaxRetries());
        vaultAccessor.setRetryIntervalMilliseconds(config.getRetryIntervalMilliseconds());
        vaultAccessor.init();

        for (VaultSecret vaultSecret : vaultSecrets) {
            String path = prefixPath + envVars.expand(vaultSecret.getPath());
            logger.printf("Retrieving secret: %s%n", path);
            Integer engineVersion = Optional.ofNullable(vaultSecret.getEngineVersion())
                .orElse(config.getEngineVersion());
            try {
                LogicalResponse response = vaultAccessor.read(path, engineVersion);
                if (responseHasErrors(config, logger, path, response)) {
                    continue;
                }
                Map<String, String> values = response.getData();
                for (VaultSecretValue value : vaultSecret.getSecretValues()) {
                    String vaultKey = value.getVaultKey();
                    String secret = values.get(vaultKey);
                    if (StringUtils.isBlank(secret) && value.getIsRequired()) {
                        throw new IllegalArgumentException(
                            "Vault Secret " + vaultKey + " at " + path
                                + " is either null or empty. Please check the Secret in Vault.");
                    }
                    overrides.put(value.getEnvVar(), secret);
                }
            } catch (VaultPluginException ex) {
                VaultException e = (VaultException) ex.getCause();
                if (e != null) {
                    throw new VaultPluginException(String
                        .format("Vault response returned %d for secret path %s",
                            e.getHttpStatusCode(), path),
                        e);
                }
                throw ex;
            }
        }

        return overrides;
    }

    public static VaultCredential retrieveVaultCredentials(Run build, VaultConfiguration config) {
        if (Jenkins.getInstanceOrNull() != null) {
            String id = config.getVaultCredentialId();
            if (StringUtils.isBlank(id)) {
                throw new VaultPluginException(
                    "The credential id was not configured - please specify the credentials to use.");
            }
            List<VaultCredential> credentials = CredentialsProvider
                .lookupCredentials(VaultCredential.class, build.getParent(), ACL.SYSTEM,
                    Collections.emptyList());
            VaultCredential credential = CredentialsMatchers
                .firstOrNull(credentials, new IdMatcher(id));

            if (credential == null) {
                throw new CredentialsUnavailableException(id);
            }

            return credential;
        }

        return null;
    }

    public static boolean responseHasErrors(VaultConfiguration configuration, PrintStream logger,
        String path, LogicalResponse response) {
        RestResponse restResponse = response.getRestResponse();
        if (restResponse == null) {
            return false;
        }
        int status = restResponse.getStatus();
        if (status == 403) {
            throw new VaultPluginException(
                String.format("Access denied to Vault path '%s'", path));
        } else if (status == 404) {
            if (configuration.getFailIfNotFound()) {
                throw new VaultPluginException(
                    String.format("Vault credentials not found for '%s'", path));
            } else {
                logger.printf("Vault credentials not found for '%s'%n", path);
                return true;
            }
        } else if (status >= 400) {
            String errors = Optional
                .of(Json.parse(new String(restResponse.getBody(), StandardCharsets.UTF_8))).map(
                    JsonValue::asObject)
                .map(j -> j.get("errors")).map(JsonValue::asArray).map(JsonArray::values)
                .map(j -> j.stream().map(JsonValue::asString).collect(Collectors.joining("\n")))
                .orElse("");
            logger.printf("Vault responded with %d error code.%n", status);
            if (StringUtils.isNotBlank(errors)) {
                logger.printf("Vault responded with errors: %s%n", errors);
            }
            return true;
        }
        return false;
    }

    public static VaultConfiguration pullAndMergeConfiguration(Run<?, ?> build,
        VaultConfiguration buildConfiguration) {
        VaultConfiguration configuration = buildConfiguration;
        for (VaultConfigResolver resolver : ExtensionList.lookup(VaultConfigResolver.class)) {
            if (configuration != null) {
                configuration = configuration
                    .mergeWithParent(resolver.forJob(build.getParent()));
            } else {
                configuration = resolver.forJob(build.getParent());
            }
        }
        if (configuration == null) {
            throw new VaultPluginException(
                "No configuration found - please configure the VaultPlugin.");
        }
        configuration.fixDefaults();

        return configuration;
    }
}
