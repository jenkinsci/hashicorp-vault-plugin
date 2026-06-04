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
import io.github.jopenlibs.vault.SslConfig;
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
        String normalizedPath = normalizePath(path);
        try {
            this.config.engineVersion(engineVersion);
            return vault.logical().read(normalizedPath);
        } catch (VaultException e) {
            throw new VaultPluginException(
                "could not read from vault: " + e.getMessage() + " at path: "
                    + normalizedPath, e);
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
        boolean verbose = Boolean.TRUE.equals(config.getVerboseLogging());
        if (verbose) {
            logger.printf("Vault: url=%s engineVersion=%s skipSslVerification=%s prefixPath=%s namespace=%s%n",
                config.getVaultUrl(), config.getEngineVersion(), config.getSkipSslVerification(),
                StringUtils.defaultString(config.getPrefixPath(), ""), StringUtils.defaultString(config.getVaultNamespace(), ""));
        }
        VaultCredential jobLevelCredential = config.getVaultCredential();

        String prefixPath = StringUtils.isBlank(config.getPrefixPath())
            ? ""
            : Util.ensureEndsWith(envVars.expand(config.getPrefixPath()), "/");

        if (vaultAccessor == null) {
            vaultAccessor = new VaultAccessor();
        }
        // Initialize a shared accessor using job-level settings when applicable; tests may inject a mock accessor
        vaultAccessor.setPolicies(generatePolicies(config.getPolicies(), envVars));
        vaultAccessor.setMaxRetries(config.getMaxRetries());
        vaultAccessor.setRetryIntervalMilliseconds(config.getRetryIntervalMilliseconds());
        boolean shouldInitSharedAccessor = (jobLevelCredential != null) || StringUtils.isNotBlank(config.getVaultCredentialId());
        if (shouldInitSharedAccessor) {
            // Resolve job-level credential by id if object is not already present
            VaultCredential resolvedJobCred = jobLevelCredential != null
                ? jobLevelCredential
                : retrieveVaultCredentials(run, config);
            vaultAccessor.setConfig(vaultConfig);
            vaultAccessor.setCredential(resolvedJobCred);
            // Allow injected mock to intercept init()
            vaultAccessor.init();
        }

        for (VaultSecret vaultSecret : vaultSecrets) {
            // Determine which credential and namespace to use for this secret
            VaultAccessor accessorToUse = vaultAccessor;
            String overrideCredId = null;
            String overrideNamespace = null;
            try {
                // Reflective-safe access to optional field; direct call is fine as we depend on same module
                overrideCredId = vaultSecret.getVaultCredentialId();
                overrideNamespace = vaultSecret.getVaultNamespace();
            } catch (NoSuchMethodError e) {
                // older configurations won't have this method/field
                overrideCredId = null;
                overrideNamespace = null;
            }
            // If there is no per-secret credential, no job-level credential object, and no job-level credential id, fail fast
            if (StringUtils.isBlank(overrideCredId) && jobLevelCredential == null && StringUtils.isBlank(config.getVaultCredentialId())) {
                String secretPathInfo = prefixPath + envVars.expand(vaultSecret.getPath());
                throw new VaultPluginException(
                    String.format("No credential configured for secret '%s'. Set a job-level credential or a per-secret credential override.",
                        secretPathInfo));
            }
            // Build per-secret config if namespace is overridden, else reuse existing
            VaultConfig perSecretConfig;
            if (StringUtils.isNotBlank(overrideNamespace)) {
                try {
                    perSecretConfig = new VaultConfig();
                    perSecretConfig.address(config.getVaultUrl());
                    perSecretConfig.engineVersion(config.getEngineVersion());
                    if (config.getSkipSslVerification()) {
                        perSecretConfig.sslConfig(new SslConfig().verify(false).build());
                    }
                    perSecretConfig.nameSpace(overrideNamespace);
                    if (StringUtils.isNotEmpty(config.getPrefixPath())) {
                        perSecretConfig.prefixPath(config.getPrefixPath());
                    }
                } catch (VaultException e) {
                    throw new VaultPluginException("Could not set up per-secret VaultConfig.", e);
                }
            } else {
                perSecretConfig = vaultConfig;
            }

            // Resolve credential to use for this secret
            VaultCredential credToUse = null;
            if (StringUtils.isNotBlank(overrideCredId)) {
                credToUse = retrieveVaultCredentialById(run, overrideCredId);
            } else {
                // Use already-initialized shared accessor when no per-secret override
                credToUse = jobLevelCredential;
            }

            if (verbose && (StringUtils.isNotBlank(overrideCredId) || StringUtils.isNotBlank(overrideNamespace))) {
                logger.printf("Using per-secret overrides: credentialId=%s namespace=%s%n",
                    StringUtils.defaultString(overrideCredId, "(job-level)"),
                    StringUtils.defaultString(overrideNamespace, "(job-level)"));
            }

            if (StringUtils.isNotBlank(overrideCredId) || StringUtils.isNotBlank(overrideNamespace)) {
                // Create and init a per-secret accessor only when overrides are provided
                VaultAccessor perSecretAccessor = new VaultAccessor();
                perSecretAccessor.setConfig(perSecretConfig);
                perSecretAccessor.setCredential(credToUse);
                perSecretAccessor.setPolicies(vaultAccessor.getPolicies());
                perSecretAccessor.setMaxRetries(vaultAccessor.getMaxRetries());
                perSecretAccessor.setRetryIntervalMilliseconds(vaultAccessor.getRetryIntervalMilliseconds());
                try {
                    perSecretAccessor.init();
                } catch (VaultPluginException ex) {
                    // Provide more context on failures during login/authorization
                    throw new VaultPluginException(
                        String.format("Failed to connect/login to Vault for secret (credentialId=%s, namespace=%s)",
                            StringUtils.defaultString(overrideCredId, StringUtils.defaultString(config.getVaultCredentialId(), "(custom-object)")),
                            StringUtils.defaultString(overrideNamespace, StringUtils.defaultString(config.getVaultNamespace(), "(default)"))), ex);
                }
                accessorToUse = perSecretAccessor;
            }
            String path = prefixPath + envVars.expand(vaultSecret.getPath());
            if (verbose) {
                logger.printf("Retrieving secret: %s%n", path);
            }
            Integer engineVersion = Optional.ofNullable(vaultSecret.getEngineVersion())
                .orElse(config.getEngineVersion());
            try {
                LogicalResponse response = accessorToUse.read(path, engineVersion);
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

    /**
     * Resolve a VaultCredential by ID scoped to the job's parent item.
     */
    public static VaultCredential retrieveVaultCredentialById(Run build, String id) {
        if (Jenkins.getInstanceOrNull() != null) {
            if (StringUtils.isBlank(id)) {
                throw new VaultPluginException(
                    "The credential id was blank - please specify the credentials to use.");
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

    public static VaultCredential retrieveVaultCredentials(Run build, VaultConfiguration config) {
        if (Jenkins.getInstanceOrNull() != null) {
            String id = config.getVaultCredentialId();
            if (StringUtils.isBlank(id)) {
                throw new VaultPluginException(
                    "The credential id was not configured - please specify the credentials to use.");
            }
            List<VaultCredential> credentials = CredentialsProvider
                .lookupCredentialsInItem(VaultCredential.class, build.getParent(), ACL.SYSTEM2,
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

    /**
     * Normalize user-supplied Vault paths so we don't send leading or duplicate slashes to Vault.
     * Leading slashes cause requests like "/v1//path" which Vault replies to with HTTP 301 for KV v1.
     */
    static String normalizePath(String path) {
        if (StringUtils.isBlank(path)) {
            return path;
        }

        // remove any leading slashes
        String cleaned = StringUtils.stripStart(path, "/");

        // fast-path: nothing to do in the common case
        if (!cleaned.contains("//")) {
            return cleaned;
        }

        // collapse duplicate separators
        return cleaned.replaceAll("/{2,}", "/");
    }
}
