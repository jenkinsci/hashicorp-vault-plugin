package com.datapipe.jenkins.vault.it;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.common.VaultUsernamePasswordCredential;
import com.datapipe.jenkins.vault.credentials.common.VaultUsernamePasswordCredentialImpl;
import hudson.FilePath;
import hudson.model.Result;
import hudson.model.Run;
import hudson.util.Secret;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getShellString;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getVariable;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@WithJenkins
class VaultUsernamePasswordCredentialIT {

    @Test
    void shouldRetrieveCorrectCredentialsFromVault(JenkinsRule j) throws Exception {
        final String credentialsId = "cloudfoundry";
        final String vaultAddr = "https://localhost:8200";
        final String username = "luke";
        final String password = "skywalker";
        final String jobId = "testJob";

        VaultUsernamePasswordCredential up = mock(
            VaultUsernamePasswordCredentialImpl.class);
        when(up.forRun(any(Run.class))).thenReturn(up);
        when(up.getId()).thenReturn(credentialsId);
        when(up.getUsername()).thenReturn(username);
        when(up.getPassword()).thenReturn(Secret.fromString(password));
        CredentialsProvider.lookupStores(j.jenkins).iterator().next()
            .addCredentials(Domain.global(), up);
        WorkflowJob p = j.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + " withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: '"
            + credentialsId
            + "', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) { "
            + "      " + getShellString() + " 'echo " + getVariable("USERNAME") + ":" + getVariable("PASSWORD") + " > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        j.assertBuildStatus(Result.SUCCESS, j.waitForCompletion(b));
        j.assertLogNotContains(password, b);
        FilePath script = j.jenkins.getWorkspaceFor(p).child("script");
        assertEquals(username + ":" + password, script.readToString().trim());
    }

    @Test
    void shouldRetrieveCorrectCredentialsFromVaultWithCustomKeys(JenkinsRule j) throws Exception {
        final String credentialsId = "custom";
        final String vaultAddr = "https://localhost:8200";
        final String username = "luke";
        final String password = "skywalker";
        final String jobId = "testJob";

        VaultUsernamePasswordCredentialImpl vup = new VaultUsernamePasswordCredentialImpl(
            null, credentialsId, "Test Credentials");
        vup.setPath("secret/custom");
        vup.setUsernameKey("name");
        vup.setPasswordKey("alias");
        vup.setEngineVersion(1);

        VaultUsernamePasswordCredentialImpl vup_spy = spy(vup);
        doReturn(credentialsId).when(vup_spy).getId();
        doReturn(username).when(vup_spy).getUsername();
        doReturn(Secret.fromString(password)).when(vup_spy).getPassword();
        CredentialsProvider.lookupStores(j.jenkins).iterator().next()
            .addCredentials(Domain.global(), vup_spy);
        WorkflowJob p = j.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + "withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: '"
            + credentialsId
            + "', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {"
            + "      " + getShellString() + " 'echo " + getVariable("USERNAME") + ":" + getVariable("PASSWORD") + " > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        j.assertBuildStatus(Result.SUCCESS, j.waitForCompletion(b));
        j.assertLogNotContains(password, b);
        FilePath script = j.jenkins.getWorkspaceFor(p).child("script");
        String log = script.readToString().trim();
        assertEquals(username + ":" + password, script.readToString().trim());
    }

    @Test
    void shouldFailIfMissingCredentials(JenkinsRule j) throws Exception {
        final String credentialsId = "cloudfoundry";
        final String token = "fakeToken";
        final String jobId = "testJob";

        VaultUsernamePasswordCredentialImpl c = new VaultUsernamePasswordCredentialImpl(
            null, credentialsId, "Test Credentials");
        c.setPath("secret/cloudfoundry");
        c.setUsernameKey(null);
        c.setPasswordKey(null);
        c.setEngineVersion(1);
        CredentialsProvider.lookupStores(j.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);
        WorkflowJob p = j.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + " withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: '"
            + credentialsId
            + "', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) { "
            + "      " + getShellString() + " 'echo " + getVariable("USERNAME") + ":" + getVariable("PASSWORD") + " > script'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        j.assertBuildStatus(Result.FAILURE, j.waitForCompletion(b));
        j.assertLogNotContains(token, b);
        j.assertLogContains("credentials", b);
    }
}
