/**
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

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;
import com.datapipe.jenkins.vault.configuration.VaultConfigResolver;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import com.datapipe.jenkins.vault.log.MaskingConsoleLogFilter;
import com.datapipe.jenkins.vault.model.VaultSecret;
import com.datapipe.jenkins.vault.model.VaultSecretValue;
import hudson.*;
import hudson.console.ConsoleLogFilter;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildWrapper;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildWrapper;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class VaultBuildWrapper extends SimpleBuildWrapper {
    private VaultConfiguration configuration;
    private List<VaultSecret> vaultSecrets;
    private List<String> valuesToMask = new ArrayList<>();

    @DataBoundConstructor
    public VaultBuildWrapper(@CheckForNull List<VaultSecret> vaultSecrets) {
        this.vaultSecrets = vaultSecrets;
    }

    @Override
    public void setUp(Context context, Run<?, ?> build, FilePath workspace,
                      Launcher launcher, TaskListener listener, EnvVars initialEnvironment)
            throws IOException, InterruptedException {
        PrintStream logger = listener.getLogger();
        pullAndMergeConfiguration(build);

        try {
            provideEnvironmentVariablesFromVault(context);
        } catch (VaultException e) {
            e.printStackTrace(logger);
            throw new AbortException(e.getMessage());
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

    private void provideEnvironmentVariablesFromVault(Context context) throws VaultException {
        String url = getConfiguration().getVaultUrl();
        String roleId = retrieveVaultCredentials().getRoleId();
        String secretId = Secret.toString(retrieveVaultCredentials().getSecretId());

        for (VaultSecret vaultSecret : vaultSecrets) {
            VaultConfig vaultConfig = new VaultConfig(url).build();

            Vault vault = new Vault(vaultConfig);
            String token = vault.auth().loginByAppRole("approle", roleId, secretId).getAuthClientToken();
            vault = new Vault(vaultConfig.token(token));
            Map<String, String> values =
                    vault.logical().read(vaultSecret.getPath()).getData();

            for (VaultSecretValue value : vaultSecret.getSecretValues()) {
                valuesToMask.add(values.get(value.getVaultKey()));
                context.env(value.getEnvVar(), values.get(value.getVaultKey()));
            }
        }
    }

    private VaultTokenCredential retrieveVaultCredentials() {
        String id = getConfiguration().getVaultTokenCredentialId();
        if (StringUtils.isBlank(id)) {
            throw new VaultPluginException("The credential id was not set - neither in the global config nor in the job config.");
        }
        List<VaultTokenCredential> credentials = CredentialsProvider.lookupCredentials(VaultTokenCredential.class, Jenkins.getInstance(), Jenkins.getAuthentication(), Collections.<DomainRequirement>emptyList());
        VaultTokenCredential credential = CredentialsMatchers.firstOrNull(credentials, new IdMatcher(id));

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
    }

    @Override
    public ConsoleLogFilter createLoggerDecorator(
            @Nonnull final Run<?, ?> build) {
        return new MaskingConsoleLogFilter(build.getCharset().name(), valuesToMask);
    }


    /**
     * Descriptor for {@link VaultBuildWrapper}. Used as a singleton. The class is marked as public so
     * that it can be accessed from views.
     */
    @Extension
    public static final class DescriptorImpl extends Descriptor<BuildWrapper> {
        public DescriptorImpl() {
            super(VaultBuildWrapper.class);
            load();
        }

        public boolean isApplicable(AbstractProject<?, ?> item) {
            // Indicates that this builder can be used with all kinds of project types
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
