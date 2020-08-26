/*
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2016 Datapipe, Inc.
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.datapipe.jenkins.vault;

import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.json.JsonArray;
import com.bettercloud.vault.json.JsonValue;
import com.bettercloud.vault.response.LogicalResponse;
import com.bettercloud.vault.rest.RestResponse;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;
import com.datapipe.jenkins.vault.configuration.VaultConfigResolver;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import com.datapipe.jenkins.vault.log.MaskingConsoleLogFilter;
import com.datapipe.jenkins.vault.model.VaultSecret;
import com.datapipe.jenkins.vault.model.VaultSecretValue;
import com.google.common.annotations.VisibleForTesting;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.EnvVars;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Util;
import hudson.console.ConsoleLogFilter;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.tasks.BuildWrapperDescriptor;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import jenkins.tasks.SimpleBuildWrapper;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class VaultBuildWrapper extends SimpleBuildWrapper {

    private VaultConfiguration configuration;
    private List<VaultSecret> vaultSecrets;
    private List<String> valuesToMask = new ArrayList<>();
    private transient VaultAccessor vaultAccessor = new VaultAccessor();
    protected PrintStream logger;

    @DataBoundConstructor
    public VaultBuildWrapper(@CheckForNull List<VaultSecret> vaultSecrets) {
        this.vaultSecrets = vaultSecrets;
    }

    @Override
    public void setUp(Context context, Run<?, ?> build, FilePath workspace,
        Launcher launcher, TaskListener listener, EnvVars initialEnvironment) {
        logger = listener.getLogger();
        pullAndMergeConfiguration(build);

        // JENKINS-44163 - Build fails with a NullPointerException when no secrets are given for a job
        if (null != vaultSecrets && !vaultSecrets.isEmpty()) {
            provideEnvironmentVariablesFromVault(context, build, initialEnvironment);
        }
    }


    public List<VaultSecret> getVaultSecrets() {
        return this.vaultSecrets;
    }

    @DataBoundSetter
    public void setConfiguration(VaultConfiguration configuration) {
        this.configuration = configuration;
    }

    public VaultConfiguration getConfiguration() {
        return this.configuration;
    }

    @VisibleForTesting
    public void setVaultAccessor(VaultAccessor vaultAccessor) {
        this.vaultAccessor = vaultAccessor;
    }

    private List<String> retrieveLeaseIds(List<LogicalResponse> logicalResponses) {
        List<String> leaseIds = new ArrayList<>();
        for (LogicalResponse response : logicalResponses) {
            String leaseId = response.getLeaseId();
            if (leaseId != null && !leaseId.isEmpty()) {
                leaseIds.add(leaseId);
            }
        }
        return leaseIds;
    }

    protected void provideEnvironmentVariablesFromVault(Context context, Run build, EnvVars envVars) {
        VaultConfiguration config = getConfiguration();
        String url = config.getVaultUrl();

        if (StringUtils.isBlank(url)) {
            throw new VaultPluginException(
                "The vault url was not configured - please specify the vault url to use.");
        }

        VaultConfig vaultConfig = config.getVaultConfig();
        VaultCredential credential = config.getVaultCredential();
        if (credential == null) credential = retrieveVaultCredentials(build);

        String prefixPath = StringUtils.isBlank(config.getPrefixPath())
            ? ""
            : Util.ensureEndsWith(envVars.expand(config.getPrefixPath()), "/");

        if (vaultAccessor == null) vaultAccessor = new VaultAccessor();
        vaultAccessor.setConfig(vaultConfig);
        vaultAccessor.setCredential(credential);
        vaultAccessor.setMaxRetries(config.getMaxRetries());
        vaultAccessor.setRetryIntervalMilliseconds(config.getRetryIntervalMilliseconds());
        vaultAccessor.init();

        for (VaultSecret vaultSecret : vaultSecrets) {
            String path = prefixPath + envVars.expand(vaultSecret.getPath());
            logger.printf("Retrieving secret: %s%n", path);
            Integer engineVersion = Optional.ofNullable(vaultSecret.getEngineVersion())
                .orElse(configuration.getEngineVersion());
            try {
                LogicalResponse response = vaultAccessor.read(path, engineVersion);
                if (responseHasErrors(path, response)) {
                    continue;
                }
                Map<String, String> values = response.getData();
                for (VaultSecretValue value : vaultSecret.getSecretValues()) {
                    String vaultKey = value.getVaultKey();
                    String secret = values.get(vaultKey);
                    if (StringUtils.isBlank(secret)) {
                        throw new IllegalArgumentException(
                            "Vault Secret " + vaultKey + " at " + path
                                + " is either null or empty. Please check the Secret in Vault.");
                    } else {
                        valuesToMask.add(secret);
                    }
                    context.env(value.getEnvVar(), secret);
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
    }

    private boolean responseHasErrors(String path, LogicalResponse response) {
        RestResponse restResponse = response.getRestResponse();
        if (restResponse == null) return false;
        int status = restResponse.getStatus();
        if (status == 403) {
            logger.printf("Access denied to Vault Secrets at '%s'%n", path);
            return true;
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
                .of(Json.parse(new String(restResponse.getBody(), StandardCharsets.UTF_8))).map(JsonValue::asObject)
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

    protected VaultCredential retrieveVaultCredentials(Run build) {
        String id = getConfiguration().getVaultCredentialId();
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

    private void pullAndMergeConfiguration(Run<?, ?> build) {
        for (VaultConfigResolver resolver : ExtensionList.lookup(VaultConfigResolver.class)) {
            if (configuration != null) {
                configuration = configuration.mergeWithParent(resolver.forJob(build.getParent()));
            } else {
                configuration = resolver.forJob(build.getParent());
            }
        }
        if (configuration == null) {
            throw new VaultPluginException(
                "No configuration found - please configure the VaultPlugin.");
        }
        configuration.fixDefaults();
    }

    @Override
    public ConsoleLogFilter createLoggerDecorator(
        @NonNull final Run<?, ?> build) {
        return new MaskingConsoleLogFilter(build.getCharset().name(), valuesToMask);
    }


    /**
     * Descriptor for {@link VaultBuildWrapper}. Used as a singleton. The class is marked as public so
     * that it can be accessed from views.
     */
    @Extension
    @Symbol("withVault")
    public static final class DescriptorImpl extends BuildWrapperDescriptor {

        public DescriptorImpl() {
            super(VaultBuildWrapper.class);
            load();
        }

        @Override
        public boolean isApplicable(AbstractProject<?, ?> item) {
            return true;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        @Override
        public String getDisplayName() {
            return "Vault Plugin";
        }
    }
}
