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

import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.log.MaskingConsoleLogFilter;
import com.datapipe.jenkins.vault.model.VaultSecret;
import com.google.common.annotations.VisibleForTesting;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.console.ConsoleLogFilter;
import hudson.model.AbstractProject;
import hudson.model.ItemGroup;
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
    private final List<VaultSecret> vaultSecrets;
    private final List<String> valuesToMask = new ArrayList<>();
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
        if (vaultSecrets == null || vaultSecrets.isEmpty()) {
            return;
        }

        provideEnvironmentVariablesFromVault(context, build, initialEnvironment);
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

    protected void provideEnvironmentVariablesFromVault(Context context, Run<?, ?> run,
        EnvVars envVars) {
        ItemGroup<?> itemGroup = run != null ? run.getParent().getParent() : null;

        Map<String, String> overrides = VaultAccessor
            .retrieveVaultSecrets(itemGroup, logger, envVars, vaultAccessor,
                getConfiguration(), getVaultSecrets());

        for (Map.Entry<String, String> secret : overrides.entrySet()) {
            valuesToMask.add(secret.getValue());
            context.env(secret.getKey(), secret.getValue());
        }
    }

    @Override
    public ConsoleLogFilter createLoggerDecorator(@NonNull final Run<?, ?> build) {
        return new MaskingConsoleLogFilter(build.getCharset().name(), valuesToMask);
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
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
