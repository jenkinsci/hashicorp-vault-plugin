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
import hudson.EnvVars;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.Util;
import hudson.console.ConsoleLogFilter;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.util.Secret;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.workflow.steps.BodyExecutionCallback.TailCall;
import org.jenkinsci.plugins.workflow.steps.BodyInvoker;
import org.jenkinsci.plugins.workflow.steps.EnvironmentExpander;
import org.jenkinsci.plugins.workflow.steps.GeneralNonBlockingStepExecution;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class VaultBindingStep extends Step {

    private VaultConfiguration configuration;
    private List<VaultSecret> vaultSecrets;

    @DataBoundConstructor
    public VaultBindingStep(@CheckForNull List<VaultSecret> vaultSecrets) {
        this.vaultSecrets = vaultSecrets;
    }

    public List<VaultSecret> getVaultSecrets() {
        return vaultSecrets;
    }

    @DataBoundSetter
    public void setConfiguration(VaultConfiguration configuration) {
        this.configuration = configuration;
    }

    public VaultConfiguration getConfiguration() {
        return configuration;
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        return new Execution(this, context);
    }

    protected static class Execution extends GeneralNonBlockingStepExecution {
        private static final long serialVersionUID = 1;

        private transient VaultBindingStep step;
        private transient VaultAccessor vaultAccessor;

        public Execution(VaultBindingStep step, StepContext context) {
            super(context);
            this.step = step;
        }

        @VisibleForTesting
        public void setVaultAccessor(VaultAccessor vaultAccessor) {
            this.vaultAccessor = vaultAccessor;
        }

        @Override
        public boolean start() throws Exception {
            run(this::doStart);
            return false;
        }

        private void doStart() throws Exception {
            Run<?, ?> run = getContext().get(Run.class);
            TaskListener listener = getContext().get(TaskListener.class);
            EnvVars envVars = getContext().get(EnvVars.class);

            Map<String, String> overrides = new HashMap<String, String>();

            VaultConfiguration config = pullAndMergeConfiguration(run);
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

            if (vaultAccessor == null) vaultAccessor = new VaultAccessor();
            vaultAccessor.setConfig(vaultConfig);
            vaultAccessor.setCredential(credential);
            vaultAccessor.setMaxRetries(config.getMaxRetries());
            vaultAccessor.setRetryIntervalMilliseconds(config.getRetryIntervalMilliseconds());
            vaultAccessor.init();

            for (VaultSecret vaultSecret : step.getVaultSecrets()) {
                String path = prefixPath + envVars.expand(vaultSecret.getPath());
                listener.getLogger().printf("Retrieving secret: %s%n", path);
                Integer engineVersion = Optional.ofNullable(vaultSecret.getEngineVersion())
                    .orElse(config.getEngineVersion());
                try {
                    LogicalResponse response = vaultAccessor.read(path, engineVersion);
                    if (responseHasErrors(config, listener, path, response)) {
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

            List<String> secretValues = new ArrayList<>();
            secretValues.addAll(overrides.values());

            getContext().newBodyInvoker().
                withContext(EnvironmentExpander.merge(getContext().get(EnvironmentExpander.class),
                    new VaultBindingStep.Overrider(overrides))).
                withContext(BodyInvoker
                    .mergeConsoleLogFilters(getContext().get(ConsoleLogFilter.class),
                        new MaskingConsoleLogFilter(run.getCharset().name(), secretValues))).
                withCallback(new Callback())
                .start();
        }

        private boolean responseHasErrors(VaultConfiguration configuration, TaskListener listener,
            String path, LogicalResponse response) {
            RestResponse restResponse = response.getRestResponse();
            if (restResponse == null) {
                return false;
            }
            int status = restResponse.getStatus();
            if (status == 403) {
                listener.getLogger().printf("Access denied to Vault Secrets at '%s'%n", path);
                return true;
            } else if (status == 404) {
                if (configuration.getFailIfNotFound()) {
                    throw new VaultPluginException(
                        String.format("Vault credentials not found for '%s'", path));
                } else {
                    listener.getLogger().printf("Vault credentials not found for '%s'%n", path);
                    return true;
                }
            } else if (status >= 400) {
                String errors = Optional
                    .of(Json.parse(new String(restResponse.getBody(), StandardCharsets.UTF_8))).map(
                        JsonValue::asObject)
                    .map(j -> j.get("errors")).map(JsonValue::asArray).map(JsonArray::values)
                    .map(j -> j.stream().map(JsonValue::asString).collect(Collectors.joining("\n")))
                    .orElse("");
                listener.getLogger().printf("Vault responded with %d error code.%n", status);
                if (StringUtils.isNotBlank(errors)) {
                    listener.getLogger().printf("Vault responded with errors: %s%n", errors);
                }
                return true;
            }
            return false;
        }

        protected VaultCredential retrieveVaultCredentials(Run build, VaultConfiguration config) {
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

        private VaultConfiguration pullAndMergeConfiguration(Run<?, ?> build) {
            VaultConfiguration configuration = null;
            for (VaultConfigResolver resolver : ExtensionList.lookup(VaultConfigResolver.class)) {
                if (step.getConfiguration() != null) {
                    configuration = step.getConfiguration()
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

    private static final class Overrider extends EnvironmentExpander {

        private static final long serialVersionUID = 1;

        private final Map<String, Secret> overrides = new HashMap<String, Secret>();

        Overrider(Map<String, String> overrides) {
            for (Map.Entry<String, String> override : overrides.entrySet()) {
                this.overrides.put(override.getKey(), Secret.fromString(override.getValue()));
            }
        }

        @Override
        public void expand(EnvVars env) throws IOException, InterruptedException {
            for (Map.Entry<String, Secret> override : overrides.entrySet()) {
                env.override(override.getKey(), override.getValue().getPlainText());
            }
        }

        @Override
        public Set<String> getSensitiveVariables() {
            return Collections.unmodifiableSet(overrides.keySet());
        }
    }

    private static class Callback extends TailCall {

        @Override
        protected void finished(StepContext context) throws Exception {

        }
    }

    @Extension
    public static final class DescriptorImpl extends StepDescriptor {

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return Collections
                .unmodifiableSet(
                    new HashSet<>(Arrays.asList(TaskListener.class, Run.class, EnvVars.class)));
        }

        @Override
        public boolean takesImplicitBlockArgument() {
            return true;
        }

        @Override
        public String getFunctionName() {
            return "withVault";
        }

        @Nonnull
        @Override
        public String getDisplayName() {
            return "Vault Plugin";
        }
    }
}
