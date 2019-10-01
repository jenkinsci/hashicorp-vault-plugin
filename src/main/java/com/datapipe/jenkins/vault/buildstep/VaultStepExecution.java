package com.datapipe.jenkins.vault.buildstep;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import hudson.EnvVars;
import hudson.Util;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.IOException;
import javax.annotation.Nonnull;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepExecution;

public class VaultStepExecution extends StepExecution {

    private static final long serialVersionUID = 3240138110787913228L;

    private final transient VaultReadStep readStep;

    private final EnvVars envVars;
    private final transient Run run;
    private final TaskListener listener;

    VaultStepExecution(@Nonnull final StepContext context, final VaultReadStep readStep)
        throws IOException, InterruptedException {
        super(context);
        this.readStep = readStep;
        this.run = getRunFromContext();
        this.listener = getTaskListenerFromContext();
        this.envVars = run.getEnvironment(listener);
    }

    @Override
    public boolean start() {
        try {
            final String path = Util.replaceMacro(readStep.getPath(), envVars);
            final Integer engineVersion = readStep.getEngineVersion();
            final VaultAccessor vaultAccessor = initVaultAccessor();

            final String value = vaultAccessor.read(path, engineVersion)
                .getData()
                .get(Util.replaceMacro(readStep.getKey(), envVars));
            getContext().onSuccess(value);
        } catch (VaultPluginException ex) {
            getContext().onFailure(ex);
        }
        return true;
    }

    @Override
    public void stop(@Nonnull final Throwable cause) {
        // no action required on stopping
    }

    private VaultAccessor initVaultAccessor() {
        GlobalVaultConfiguration globalVaultConfiguration = GlobalVaultConfiguration.get();

        final VaultConfiguration vaultConfiguration = globalVaultConfiguration.getConfiguration();
        final String credentialsId = StringUtils.isBlank(readStep.getCredentialsId()) ? vaultConfiguration.getVaultCredentialId() : Util.replaceMacro(readStep.getCredentialsId(), envVars);
        final String vaultUrl = StringUtils.isBlank(readStep.getVaultUrl()) ? vaultConfiguration.getVaultUrl() : Util.replaceMacro(readStep.getVaultUrl(), envVars);
        final boolean skipSslVerification = vaultConfiguration.isSkipSslVerification();

        VaultAccessor vaultAccessor = new VaultAccessor();

        if (StringUtils.isBlank(credentialsId)) {
            listener.getLogger().append(String.format("using vault url '%s' without credentials", vaultUrl));
            vaultAccessor.init(vaultUrl, skipSslVerification);
            return vaultAccessor;
        } else {
            listener.getLogger().append(String.format("using vault url '%s' and credentialsId '%s'", vaultUrl, credentialsId));
        }

        VaultCredential credential = CredentialsProvider.findCredentialById(credentialsId, VaultCredential.class, run);

        if (credential == null) {
            listener.getLogger().append(String.format("no credentials found for credentialId %s, accessing Vault without credentials", credentialsId));
            vaultAccessor.init(vaultUrl, skipSslVerification);
        } else {
            vaultAccessor.init(vaultUrl, credential, skipSslVerification);
        }
        return vaultAccessor;
    }

    private Run getRunFromContext() throws IOException, InterruptedException {
        Run runFromContext = getContext().get(Run.class);
        if (runFromContext == null) {
            throw new VaultPluginException("Environment not set up properly - Run from context is null.");
        }
        return runFromContext;
    }

    private TaskListener getTaskListenerFromContext() throws IOException, InterruptedException {
        TaskListener listenerFromContext = getContext().get(TaskListener.class);
        if (listenerFromContext == null) {
            throw new VaultPluginException("Environment not set up properly - TaskListener from context is null.");
        }
        return listenerFromContext;
    }
}
