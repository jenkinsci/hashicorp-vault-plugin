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
 * <p>The field to read can be given two ways:
 * <ul>
 *     <li>explicitly via the {@code key} parameter (in which case {@code path} is used verbatim), or</li>
 *     <li>folded into {@code path}, where the last segment after the final {@code /} is the field key
 *     and everything before it is the secret path. This applies only when {@code key} is absent.</li>
 * </ul>
 *
 * <pre>
 * environment {
 *     // explicit key (drop-in compatible with the hashicorp-vault-pipeline-plugin `vault` step)
 *     DB_USER = vault path: 'secret/myapp/db', key: 'username', engineVersion: '2'
 *
 *     // key folded into path
 *     DB_HOST = vault(path: 'secret/myapp/db/host', credentialsId: 'vault-approle')
 *     DB_PASS = vault(path: 'secret/myapp/db/password', credentialsId: 'vault-approle',
 *                   vaultUrl: 'https://vault:8200', vaultNamespace: 'prod')
 * }
 * </pre>
 *
 * <p><b>Breaking change:</b> this step is registered under the function name {@code vault}. It
 * supersedes the {@code vaultCredentials} step name shipped in release {@code 381.v4277b_9fa_a_380}
 * (#367); that name is no longer registered. Pipelines that adopted {@code vaultCredentials(...)}
 * must switch to {@code vault(...)}. Aligning on the {@code vault} name is what makes migrating off
 * the abandoned hashicorp-vault-pipeline-plugin a drop-in (see #369).
 *
 * <p>When {@code credentialsId} is omitted the global Vault configuration's credential is used.
 *
 * <p>When {@code maskSecret} is {@code true} (the default), the resolved value is registered with
 * {@link VaultMaskedValuesFilter} so it is automatically redacted from subsequent console output.
 */
public class VaultStep extends Step {

    private final String path;
    private String key;
    private String credentialsId;
    private String vaultUrl;
    private String vaultNamespace;
    private String engineVersion;
    private boolean maskSecret = true;

    @DataBoundConstructor
    public VaultStep(@NonNull String path) {
        this.path = path;
    }

    @DataBoundSetter
    public void setKey(@CheckForNull String key) {
        this.key = StringUtils.trimToNull(key);
    }

    @DataBoundSetter
    public void setCredentialsId(@CheckForNull String credentialsId) {
        this.credentialsId = StringUtils.trimToNull(credentialsId);
    }

    @DataBoundSetter
    public void setVaultUrl(@CheckForNull String vaultUrl) {
        this.vaultUrl = StringUtils.trimToNull(vaultUrl);
    }

    @DataBoundSetter
    public void setVaultNamespace(@CheckForNull String vaultNamespace) {
        this.vaultNamespace = StringUtils.trimToNull(vaultNamespace);
    }

    /**
     * Per-call KV engine version override. Declared as a String (e.g. {@code '1'} or {@code '2'}) to
     * match the old {@code vault path: '...', engineVersion: '2'} syntax exactly, so existing
     * pipelines bind as-is. Quote the value, as the old step required.
     */
    @DataBoundSetter
    public void setEngineVersion(@CheckForNull String engineVersion) {
        this.engineVersion = StringUtils.trimToNull(engineVersion);
    }

    @DataBoundSetter
    public void setMaskSecret(boolean maskSecret) {
        this.maskSecret = maskSecret;
    }

    public String getPath() {
        return path;
    }

    @CheckForNull
    public String getKey() {
        return key;
    }

    @CheckForNull
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

    @CheckForNull
    public String getEngineVersion() {
        return engineVersion;
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
        if (engineVersion != null) {
            try {
                localConfig.setEngineVersion(Integer.valueOf(engineVersion));
            } catch (NumberFormatException e) {
                throw new VaultPluginException(
                    "engineVersion must be an integer, got: " + engineVersion);
            }
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

        private final transient VaultStep step;

        Execution(VaultStep step, StepContext context) {
            super(context);
            this.step = step;
        }

        @Override
        protected String run() throws Exception {
            String path;
            String key;
            if (StringUtils.isNotBlank(step.key)) {
                // Explicit key: path is used verbatim (compatible with the old `vault` step).
                path = step.path;
                key = step.key;
            } else {
                // No explicit key: the last path segment is the field name.
                int lastSlash = step.path.lastIndexOf('/');
                if (lastSlash <= 0 || lastSlash == step.path.length() - 1) {
                    throw new VaultPluginException(
                        "path must be in 'path/to/secret/keyName' format (or supply a separate 'key'), got: "
                            + step.path);
                }
                path = step.path.substring(0, lastSlash);
                key = step.path.substring(lastSlash + 1);
            }

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
            return "vault";
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "Fetch a Vault KV secret value";
        }
    }
}
