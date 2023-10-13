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

import com.datapipe.jenkins.vault.configuration.VaultConfigResolver;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import com.datapipe.jenkins.vault.log.MaskingConsoleLogFilter;
import com.datapipe.jenkins.vault.model.VaultSecret;
import com.google.common.annotations.VisibleForTesting;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.EnvVars;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.FilePath;
import hudson.Launcher;
import hudson.console.ConsoleLogFilter;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildWrapperDescriptor;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import jenkins.tasks.SimpleBuildWrapper;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class VaultBuildWrapper extends SimpleBuildWrapper {

    private VaultConfiguration configuration;
    private List<VaultSecret> vaultSecrets;
    private List<String> valuesToMask = new ArrayList<>();
    private transient VaultAccessor vaultAccessor = new VaultAccessor();
    protected transient PrintStream logger;

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

    protected void provideEnvironmentVariablesFromVault(Context context, Run build,
        EnvVars envVars) {
        Map<String, String> overrides = VaultAccessor
            .retrieveVaultSecrets(build, logger, envVars, vaultAccessor,
                getConfiguration(), getVaultSecrets());

        for (Map.Entry<String, String> secret : overrides.entrySet()) {
            valuesToMask.add(secret.getValue());
            context.env(secret.getKey(), secret.getValue());
        }
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
     * Descriptor for {@link VaultBuildWrapper}. Used as a singleton. The class is marked as public
     * so that it can be accessed from views.
     */
    @Extension
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
