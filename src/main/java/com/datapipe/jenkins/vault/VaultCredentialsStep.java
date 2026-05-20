package com.datapipe.jenkins.vault;

import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Run;
import hudson.model.TaskListener;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.response.LogicalResponse;
import java.io.Serial;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.jenkinsci.plugins.workflow.steps.SynchronousNonBlockingStepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Pipeline step that fetches a single value from a Vault KV secret and returns it as a String.
 * Designed for use inside Declarative Pipeline {@code environment {}} blocks.
 *
 * <p>The {@code path} parameter combines the KV path and field name: the last segment after the
 * final {@code /} is used as the field key, and everything before it is the secret path.
 *
 * <pre>
 * environment {
 *     DB_HOST = vaultCredentials(path: 'secret/myapp/db/host', credentialsId: 'vault-approle')
 *     DB_PASS = vaultCredentials(path: 'secret/myapp/db/password', credentialsId: 'vault-approle',
 *                   vaultUrl: 'https://vault:8200', vaultNamespace: 'prod')
 * }
 * </pre>
 *
 * <p>When {@code maskSecret} is {@code true} (the default), the resolved value is registered with
 * {@link VaultMaskedValuesFilter} so it is automatically redacted from subsequent console output.
 */
public class VaultCredentialsStep extends Step {

    private final String path;
    private final String credentialsId;
    private String vaultUrl;
    private String vaultNamespace;
    private boolean maskSecret = true;

    @DataBoundConstructor
    public VaultCredentialsStep(@NonNull String path, @NonNull String credentialsId) {
        this.path = path;
        this.credentialsId = credentialsId;
    }

    @DataBoundSetter
    public void setVaultUrl(@CheckForNull String vaultUrl) {
        this.vaultUrl = StringUtils.trimToNull(vaultUrl);
    }

    @DataBoundSetter
    public void setVaultNamespace(@CheckForNull String vaultNamespace) {
        this.vaultNamespace = StringUtils.trimToNull(vaultNamespace);
    }

    @DataBoundSetter
    public void setMaskSecret(boolean maskSecret) {
        this.maskSecret = maskSecret;
    }

    public String getPath() {
        return path;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    @CheckForNull
    public String getVaultUrl() {
        return vaultUrl;
    }

    @CheckForNull
    public String getVaultNamespace() {
        return vaultNamespace;
    }

    public boolean isMaskSecret() {
        return maskSecret;
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        return new Execution(this, context);
    }

    protected String fetchValue(String path, String key, Run<?, ?> run, TaskListener listener) {
        VaultConfiguration localConfig = new VaultConfiguration();
        if (vaultUrl != null) {
            localConfig.setVaultUrl(vaultUrl);
        }
        if (vaultNamespace != null) {
            localConfig.setVaultNamespace(vaultNamespace);
        }
        if (StringUtils.isNotBlank(credentialsId)) {
            localConfig.setVaultCredentialId(credentialsId);
        }

        VaultConfiguration config = VaultAccessor.pullAndMergeConfiguration(run, localConfig);

        if (StringUtils.isBlank(config.getVaultUrl())) {
            throw new VaultPluginException(
                "vaultUrl is not configured - set it inline or via global Vault configuration");
        }

        VaultCredential credential = config.getVaultCredential();
        if (credential == null) {
            credential = VaultAccessor.retrieveVaultCredentials(run, config);
        }

        VaultConfig vaultConfig = config.getVaultConfig();
        VaultAccessor accessor = new VaultAccessor(vaultConfig, credential);
        accessor.setConfig(vaultConfig);
        accessor.setCredential(credential);
        accessor.setMaxRetries(config.getMaxRetries());
        accessor.setRetryIntervalMilliseconds(config.getRetryIntervalMilliseconds());
        accessor.init();

        LogicalResponse response = accessor.read(path, config.getEngineVersion());

        if (VaultAccessor.responseHasErrors(config, listener.getLogger(), path, response)) {
            return "";
        }

        Map<String, String> data = response.getData();
        String value = data != null ? data.get(key) : null;

        if (StringUtils.isBlank(value)) {
            if (config.getFailIfNotFound()) {
                throw new VaultPluginException(
                    "Key '" + key + "' not found at Vault path '" + path + "'");
            }
            return "";
        }

        return value;
    }

    static class Execution extends SynchronousNonBlockingStepExecution<String> {

        @Serial
        private static final long serialVersionUID = 1L;

        private final transient VaultCredentialsStep step;

        Execution(VaultCredentialsStep step, StepContext context) {
            super(context);
            this.step = step;
        }

        @Override
        protected String run() throws Exception {
            int lastSlash = step.path.lastIndexOf('/');
            if (lastSlash <= 0 || lastSlash == step.path.length() - 1) {
                throw new VaultPluginException(
                    "path must be in 'path/to/secret/keyName' format, got: " + step.path);
            }
            String path = step.path.substring(0, lastSlash);
            String key = step.path.substring(lastSlash + 1);

            Run<?, ?> run = getContext().get(Run.class);
            TaskListener listener = getContext().get(TaskListener.class);

            String value = step.fetchValue(path, key, run, listener);

            if (step.maskSecret && StringUtils.isNotBlank(value)) {
                VaultMaskedValuesAction action = run.getAction(VaultMaskedValuesAction.class);
                if (action == null) {
                    action = new VaultMaskedValuesAction();
                    run.addOrReplaceAction(action);
                }
                action.add(value);
            }

            return value;
        }
    }

    @Extension
    public static final class DescriptorImpl extends StepDescriptor {

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return Set.of(Run.class, TaskListener.class);
        }

        @Override
        public boolean takesImplicitBlockArgument() {
            return false;
        }

        @Override
        public String getFunctionName() {
            return "vaultCredentials";
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "Fetch a Vault KV secret value";
        }
    }
}
