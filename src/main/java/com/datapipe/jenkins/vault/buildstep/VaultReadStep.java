package com.datapipe.jenkins.vault.buildstep;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.DescriptorImpl.DEFAULT_ENGINE_VERSION;

import java.util.HashSet;
import java.util.Set;

import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import hudson.Extension;
import hudson.model.Run;
import hudson.model.TaskListener;

public class VaultReadStep extends Step {

    private String credentialsId;
    private String key;
    private String path;
    private String vaultUrl;
    private Integer engineVersion;

    @DataBoundConstructor
    public VaultReadStep() {}

    @DataBoundSetter
    public void setCredentialsId(final String credentialsId) {
        this.credentialsId = credentialsId;
    }

    @DataBoundSetter
    public void setKey(final String key) {
        this.key = key;
    }

    @DataBoundSetter
    public void setPath(final String path) {
        this.path = path;
    }

    @DataBoundSetter
    public void setVaultUrl(final String vaultUrl) {
        this.vaultUrl = vaultUrl;
    }

    @DataBoundSetter
    public void setEngineVersion(final int engineVersion) {
        this.engineVersion = engineVersion;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    public String getKey() {
        return key;
    }

    public String getPath() {
        return path;
    }

    public String getVaultUrl() {
        return vaultUrl;
    }

    public Integer getEngineVersion() {
        return engineVersion != null ? engineVersion : DEFAULT_ENGINE_VERSION;
    }

    @Override
    public StepExecution start(final StepContext context) throws Exception {
        return new VaultStepExecution(context, this);
    }

    @Extension
    public static final class DesciptorImpl extends StepDescriptor {

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            HashSet<Class<?>> requiredContext = new HashSet<>();
            requiredContext.add(Run.class);
            requiredContext.add(TaskListener.class);
            return requiredContext;
        }

        @Override
        public String getFunctionName() {
            return "vault";
        }
    }
}
