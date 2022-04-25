package com.datapipe.jenkins.vault.it;

import com.bettercloud.vault.api.Auth;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.VaultAppRoleCredential;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import hudson.FilePath;
import hudson.model.Result;
import hudson.util.Secret;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getShellString;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getVariable;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

public class VaultTokenCredentialBindingIT {

    @Rule
    public RestartableJenkinsRule story = new RestartableJenkinsRule();

    @Test
    public void shouldInjectCredentialsForAppRole() {
        final String credentialsId = "creds";
        final String vaultAddr = "https://localhost:8200";
        final String token = "fakeToken";
        final String jobId = "testJob";
        story.then(r -> {
            VaultAppRoleCredential c = new VaultAppRoleCredential(CredentialsScope.GLOBAL,
                credentialsId, "fake description", "roleId", Secret.fromString("fakeAppRoleToken"), "path");
            VaultAppRoleCredential spy = spy(c);
            doReturn(token).when(spy).getToken(any(Auth.class));
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), spy);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', credentialsId: '"
                + credentialsId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
                + "      " + getShellString() + " 'echo " + getVariable("VAULT_ADDR") + ":"
                + getVariable("VAULT_TOKEN") + " > script'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.SUCCESS, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(token, b);
            FilePath script = story.j.jenkins.getWorkspaceFor(p).child("script");
            assertEquals(vaultAddr + ":" + token, script.readToString().trim());
        });
    }

    @Test
    public void shouldInjectCredentialsForToken() {
        final String credentialsId = "creds";
        final String vaultAddr = "https://localhost:8200";
        final String token = "fakeToken";
        final String jobId = "testJob";
        story.then(r -> {
            VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
                credentialsId, "fake description", Secret.fromString(token));
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), c);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', credentialsId: '"
                + credentialsId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
                + "      " + getShellString() + " 'echo " + getVariable("VAULT_ADDR") + ":"
                + getVariable("VAULT_TOKEN") + " > script'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.SUCCESS, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(token, b);
            FilePath script = story.j.jenkins.getWorkspaceFor(p).child("script");
            assertEquals(vaultAddr + ":" + token, script.readToString().trim());
        });
    }

    @Test
    public void shouldFailIfMissingCredentials() {
        final String credentialsId = "creds";
        final String invalidCredentialId = "nonexistentCredId";
        final String vaultAddr = "https://localhost:8200";
        final String token = "fakeToken";
        final String jobId = "testJob";
        story.then(r -> {
            VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
                credentialsId, "fake description", Secret.fromString(token));
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), c);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', credentialsId: '"
                + invalidCredentialId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
                + "      " + getShellString() + " 'echo " + getVariable("VAULT_ADDR") + ":"
                + getVariable("VAULT_TOKEN") + " > script'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.FAILURE, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(token, b);
            story.j.assertLogContains("credentials", b);
        });
    }

    @Test
    public void shouldFailIfMissingVaultAddress() {
        final String credentialsId = "creds";
        final String token = "fakeToken";
        final String jobId = "testJob";
        story.then(r -> {
            VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
                credentialsId, "fake description", Secret.fromString(token));
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), c);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'VAULT_ADDR', tokenVariable: 'VAULT_TOKEN', credentialsId: '"
                + credentialsId + "']]) {\n"
                + "      " + getShellString() + " 'echo \"" + getVariable("VAULT_ADDR") + ":"
                + getVariable("VAULT_TOKEN") + "\" > script'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.FAILURE, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(token, b);
        });
    }

    @Test
    public void shouldUseSpecifiedEnvironmentVariables() {
        final String credentialsId = "creds";
        final String vaultAddr = "https://localhost:8200";
        final String token = "fakeToken";
        final String jobId = "testJob";
        story.then(r -> {
            VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
                credentialsId, "fake description", Secret.fromString(token));
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), c);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + "  withCredentials([[$class: 'VaultTokenCredentialBinding', addrVariable: 'FOO', tokenVariable: 'BAR', credentialsId: '"
                + credentialsId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
                + "      " + getShellString() + " 'echo " + getVariable("FOO") + ":"
                + getVariable("BAR") + " > script'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.SUCCESS, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(token, b);
            FilePath script = story.j.jenkins.getWorkspaceFor(p).child("script");
            assertEquals(vaultAddr + ":" + token, script.readToString().trim());
        });
    }

    @Test
    public void shouldUseDefaultsIfVariablesAreOmitted() {
        final String credentialsId = "creds";
        final String vaultAddr = "https://localhost:8200";
        final String token = "fakeToken";
        final String jobId = "testJob";
        story.then(r -> {
            VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
                credentialsId, "fake description", Secret.fromString(token));
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), c);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + "  withCredentials([[$class: 'VaultTokenCredentialBinding', credentialsId: '"
                + credentialsId + "', vaultAddr: '" + vaultAddr + "']]) {\n"
                + "      " + getShellString() + " 'echo " + getVariable("VAULT_ADDR") + ":"
                + getVariable("VAULT_TOKEN") + " > script'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.SUCCESS, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(token, b);
            FilePath script = story.j.jenkins.getWorkspaceFor(p).child("script");
            assertEquals(vaultAddr + ":" + token, script.readToString().trim());
        });
    }
}
