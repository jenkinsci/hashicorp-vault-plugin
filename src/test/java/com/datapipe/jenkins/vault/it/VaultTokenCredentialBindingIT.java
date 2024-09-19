package com.datapipe.jenkins.vault.it;

import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.api.Auth;
import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.configuration.FolderVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultAppRoleCredential;
import com.datapipe.jenkins.vault.credentials.VaultCredential.VaultAuthorizationResult;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import com.datapipe.jenkins.vault.credentials.common.VaultGCRLoginImpl;
import hudson.FilePath;
import hudson.model.Result;
import hudson.util.Secret;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getShellString;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getVariable;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

public class VaultTokenCredentialBindingIT {

    @Rule
    public JenkinsRule rule = new JenkinsRule();

    @Before
    public void setUp() {
        CredentialsStore store = CredentialsProvider.lookupStores(rule.jenkins).iterator().next();
        store.getCredentials(Domain.global()).forEach(c -> {
            try {
                store.removeCredentials(Domain.global(), c);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    public void shouldFailForMissingCredential() throws Exception {
        final String credentialsId = "creds";
        final String vaultAddr = "https://localhost:8200";
        final String jobId = "testJob";
        WorkflowJob p = rule.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', credentialsId: '"
            + credentialsId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
            + "      " + getShellString() + " 'echo " + getVariable("VAULT_ADDR") + ":"
            + getVariable("VAULT_TOKEN") + " > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        rule.assertBuildStatus(Result.FAILURE, rule.waitForCompletion(b));
        rule.assertLogContains("Could not find credentials entry with ID '" + credentialsId + "'", b);
    }

    @Test
    public void shouldFailForIncorrectCredentialType() throws Exception {
        final String credentialsId = "creds";
        final String vaultAddr = "https://localhost:8200";
        final String jobId = "testJob";
        VaultGCRLoginImpl c = new VaultGCRLoginImpl(CredentialsScope.GLOBAL, credentialsId,
            "fake description");
        CredentialsProvider.lookupStores(rule.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);
        WorkflowJob p = rule.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', credentialsId: '"
            + credentialsId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
            + "      " + getShellString() + " 'echo " + getVariable("VAULT_ADDR") + ":"
            + getVariable("VAULT_TOKEN") + " > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        rule.assertBuildStatus(Result.FAILURE, rule.waitForCompletion(b));
        rule.assertLogContains("Credentials '" + credentialsId +
            "' is of type 'Vault Google Container Registry Login'", b);
    }

    @Test
    public void shouldInjectCredentialsForAppRole() throws Exception {
        final String credentialsId = "creds";
        final String vaultAddr = "https://localhost:8200";
        final String token = "fakeToken";
        final String jobId = "testJob";
        VaultAppRoleCredential c = new VaultAppRoleCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", "roleId", Secret.fromString("fakeAppRoleToken"), "path");
        VaultAppRoleCredential spy = spy(c);
        doReturn(token).when(spy).getToken(any(Auth.class));
        CredentialsProvider.lookupStores(rule.jenkins).iterator().next()
            .addCredentials(Domain.global(), spy);
        WorkflowJob p = rule.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', credentialsId: '"
            + credentialsId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
            + "      " + getShellString() + " 'echo " + getVariable("VAULT_ADDR") + ":"
            + getVariable("VAULT_TOKEN") + " > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        rule.assertBuildStatus(Result.SUCCESS, rule.waitForCompletion(b));
        rule.assertLogNotContains(token, b);
        FilePath script = rule.jenkins.getWorkspaceFor(p).child("script");
        assertEquals(vaultAddr + ":" + token, script.readToString().trim());
    }

    @Test
    public void shouldUseChildTokenWhenPoliciesConfigured() throws Exception {
        final String credentialsId = "creds";
        final String vaultAddr = "https://localhost:8200";
        final String token = "fakeToken";
        final String jobId = "testJob";
        VaultAppRoleCredential c = new VaultAppRoleCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", "roleId", Secret.fromString("fakeAppRoleToken"), "path");
        VaultAppRoleCredential spy = spy(c);
        List<String> expectedPolicies = new ArrayList<>();
        expectedPolicies.add("pol1");
        expectedPolicies.add("pol_job_testJob");
        expectedPolicies.add("pol_folder_testFolder");
        doReturn(new VaultAuthorizationResult(null, token))
            .when(spy).authorizeWithVault(any(VaultConfig.class), eq(expectedPolicies));
        CredentialsProvider.lookupStores(rule.jenkins).iterator().next()
            .addCredentials(Domain.global(), spy);

        // Configure folder
        VaultConfiguration folderConfig = new VaultConfiguration();
        folderConfig.setPolicies("pol1\npol_job_${job_base_name}\npol_folder_${job_folder}");
        Folder folder = new Folder(rule.jenkins.getItemGroup(), "testFolder");
        rule.jenkins.add(folder, folder.getName());
        folder.addProperty(new FolderVaultConfiguration(folderConfig));

        WorkflowJob p = folder.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', credentialsId: '"
            + credentialsId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
            + "      " + getShellString() + " 'echo " + getVariable("VAULT_ADDR") + ":"
            + getVariable("VAULT_TOKEN") + " > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        rule.assertBuildStatus(Result.SUCCESS, rule.waitForCompletion(b));
        rule.assertLogNotContains(token, b);
        FilePath script = rule.jenkins.getWorkspaceFor(p).child("script");
        assertEquals(vaultAddr + ":" + token, script.readToString().trim());
    }

    @Test
    public void shouldInjectCredentialsForToken() throws Exception {
        final String credentialsId = "creds";
        final String vaultAddr = "https://localhost:8200";
        final String token = "fakeToken";
        final String jobId = "testJob";
        VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", Secret.fromString(token));
        CredentialsProvider.lookupStores(rule.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);
        WorkflowJob p = rule.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', credentialsId: '"
            + credentialsId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
            + "      " + getShellString() + " 'echo " + getVariable("VAULT_ADDR") + ":"
            + getVariable("VAULT_TOKEN") + " > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        rule.assertBuildStatus(Result.SUCCESS, rule.waitForCompletion(b));
        rule.assertLogNotContains(token, b);
        FilePath script = rule.jenkins.getWorkspaceFor(p).child("script");
        assertEquals(vaultAddr + ":" + token, script.readToString().trim());
    }

    @Test
    public void shouldFailIfMissingCredentials() throws Exception {
        final String credentialsId = "creds";
        final String invalidCredentialId = "nonexistentCredId";
        final String vaultAddr = "https://localhost:8200";
        final String token = "fakeToken";
        final String jobId = "testJob";
        VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", Secret.fromString(token));
        CredentialsProvider.lookupStores(rule.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);
        WorkflowJob p = rule.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', credentialsId: '"
            + invalidCredentialId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
            + "      " + getShellString() + " 'echo " + getVariable("VAULT_ADDR") + ":"
            + getVariable("VAULT_TOKEN") + " > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        rule.assertBuildStatus(Result.FAILURE, rule.waitForCompletion(b));
        rule.assertLogNotContains(token, b);
        rule.assertLogContains("credentials", b);
    }

    @Test
    public void shouldFailIfMissingVaultAddress() throws Exception {
        final String credentialsId = "creds";
        final String token = "fakeToken";
        final String jobId = "testJob";
        VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", Secret.fromString(token));
        CredentialsProvider.lookupStores(rule.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);
        WorkflowJob p = rule.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', credentialsId: '"
            + credentialsId + "']]) {\n"
            + "      " + getShellString() + " 'echo \"" + getVariable("VAULT_ADDR") + ":"
            + getVariable("VAULT_TOKEN") + "\" > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        rule.assertBuildStatus(Result.FAILURE, rule.waitForCompletion(b));
        rule.assertLogNotContains(token, b);
    }

    @Test
    public void shouldFallbackToFolderConfig() throws Exception {
        final String credentialsId = "creds";
        final String token = "fakeToken";
        final String jobId = "testJob";
        VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", Secret.fromString(token));
        CredentialsProvider.lookupStores(rule.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);

        // Configure folder
        VaultConfiguration folderConfig = new VaultConfiguration();
        folderConfig.setVaultNamespace("testNamespace");
        folderConfig.setVaultUrl("https://test-vault");
        folderConfig.setVaultCredentialId(credentialsId);
        Folder folder = new Folder(rule.jenkins.getItemGroup(), "testFolder");
        rule.jenkins.add(folder, folder.getName());
        folder.addProperty(new FolderVaultConfiguration(folderConfig));

        WorkflowJob p = folder.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', namespaceVariable: 'VAULT_NAMESPACE']]) {\n"
            + "      " + getShellString() + " 'echo \"" + getVariable("VAULT_ADDR") + ":"
            + getVariable("VAULT_TOKEN") + ":"
            + getVariable("VAULT_NAMESPACE") + "\" > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        rule.assertBuildStatus(Result.SUCCESS, rule.waitForCompletion(b));
        rule.assertLogNotContains(token, b);
        rule.assertLogNotContains(folderConfig.getVaultNamespace(), b);
        rule.assertLogNotContains(folderConfig.getVaultUrl(), b);
    }

    @Test
    public void shouldUseSpecifiedEnvironmentVariables() throws Exception {
        final String credentialsId = "creds";
        final String vaultAddr = "https://localhost:8200";
        final String token = "fakeToken";
        final String jobId = "testJob";
        VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", Secret.fromString(token));
        CredentialsProvider.lookupStores(rule.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);
        WorkflowJob p = rule.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'FOO', tokenVariable: 'BAR', credentialsId: '"
            + credentialsId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
            + "      " + getShellString() + " 'echo " + getVariable("FOO") + ":"
            + getVariable("BAR") + " > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        rule.assertBuildStatus(Result.SUCCESS, rule.waitForCompletion(b));
        rule.assertLogNotContains(token, b);
        FilePath script = rule.jenkins.getWorkspaceFor(p).child("script");
        assertEquals(vaultAddr + ":" + token, script.readToString().trim());
    }

    @Test
    public void shouldUseDefaultsIfVariablesAreOmitted() throws Exception {
        final String credentialsId = "creds";
        final String vaultAddr = "https://localhost:8200";
        final String token = "fakeToken";
        final String jobId = "testJob";
        VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", Secret.fromString(token));
        CredentialsProvider.lookupStores(rule.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);
        WorkflowJob p = rule.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + "  withCredentials([[$class: 'VaultTokenCredentialBinding', credentialsId: '"
            + credentialsId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
            + "      " + getShellString() + " 'echo " + getVariable("VAULT_ADDR") + ":"
            + getVariable("VAULT_TOKEN") + " > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        rule.assertBuildStatus(Result.SUCCESS, rule.waitForCompletion(b));
        rule.assertLogNotContains(token, b);
        FilePath script = rule.jenkins.getWorkspaceFor(p).child("script");
        assertEquals(vaultAddr + ":" + token, script.readToString().trim());
    }
}
