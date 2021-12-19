package com.datapipe.jenkins.vault;

import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.response.LogicalResponse;
import com.bettercloud.vault.rest.RestResponse;
import com.datapipe.jenkins.vault.credentials.VaultAppRoleCredential;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.model.VaultSecret;
import hudson.EnvVars;
import hudson.Extension;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.Secret;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.DataBoundConstructor;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class VaultBindingStepWithMockAccessor extends VaultBindingStep {
    @DataBoundConstructor
    public VaultBindingStepWithMockAccessor(List<VaultSecret> vaultSecrets) {
        super(vaultSecrets);
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        Execution execution = new Execution(this, context);
        execution.setVaultAccessor(new VaultAccessor() {

            @Override
            public void setConfig(VaultConfig config) {
                if (!config.getAddress().equals("http://jenkinsfile-vault-url.com")) {
                    throw new AssertionError(
                        "URL " + config.getAddress() + " does not match expected value of "
                            + "http://jenkinsfile-vault-url.com");
                }
            }

            @Override
            public void setCredential(VaultCredential credential) {
                VaultAppRoleCredential appRoleCredential = (VaultAppRoleCredential) credential;
                if (!appRoleCredential.getRoleId().equals("role-id-global-2") || !Secret.toString(appRoleCredential
                    .getSecretId()).equals("secret-id-global-2")) {
                    throw new AssertionError(
                        "role-id " + appRoleCredential.getRoleId() + " or secret-id "
                            + appRoleCredential.getSecretId()
                            + " do not match expected: -global-2");
                }
            }

            @Override
            public VaultAccessor init() {
                return this;
            }

            @Override
            public LogicalResponse read(String path, Integer engineVersion) {
                if (!path.equals("secret/path1")) {
                    throw new AssertionError(
                        "path " + path + " does not match expected: secret/path1");
                }
                Map<String, String> returnValue = new HashMap<>();
                returnValue.put("key1", "some-secret");
                LogicalResponse resp = mock(LogicalResponse.class);
                RestResponse rest = mock(RestResponse.class);
                when(resp.getData()).thenReturn(returnValue);
                when(resp.getData()).thenReturn(returnValue);
                when(resp.getRestResponse()).thenReturn(rest);
                when(rest.getStatus()).thenReturn(200);
                return resp;
            }
        });
        return execution;
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
            return "withVaultMock";
        }

        @Nonnull
        @Override
        public String getDisplayName() {
            return "Vault Mock Plugin";
        }
    }
}
