package com.datapipe.jenkins.vault.it;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.common.VaultUsernamePasswordCredential;
import com.datapipe.jenkins.vault.credentials.common.VaultUsernamePasswordCredentialImpl;
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
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class VaultUsernamePasswordCredentialIT {

    @Rule
    public RestartableJenkinsRule story = new RestartableJenkinsRule();

    @Test
    public void shouldRetrieveCorrectCredentialsFromVault() {
        final String credentialsId = "cloudfoundry";
        final String vaultAddr = "https://localhost:8200";
        final String username = "luke";
        final String password = "skywalker";
        final String jobId = "testJob";
        story.then(r -> {
            VaultUsernamePasswordCredential up = mock(
                VaultUsernamePasswordCredentialImpl.class);
            when(up.getId()).thenReturn(credentialsId);
            when(up.getUsername()).thenReturn(username);
            when(up.getPassword()).thenReturn(Secret.fromString(password));
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), up);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + " withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: '"
                + credentialsId
                + "', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) { "
                + "      " + getShellString() + " 'echo " + getVariable("USERNAME") + ":" + getVariable("PASSWORD") + " > script'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.SUCCESS, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(password, b);
            FilePath script = story.j.jenkins.getWorkspaceFor(p).child("script");
            assertEquals(username + ":" + password, script.readToString().trim());
        });
    }

    @Test
    public void shouldRetrieveCorrectCredentialsFromVaultWithCustomKeys() {
        final String credentialsId = "custom";
        final String vaultAddr = "https://localhost:8200";
        final String username = "luke";
        final String password = "skywalker";
        final String jobId = "testJob";
        story.then(r -> {
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
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), vup_spy);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + "withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: '"
                + credentialsId
                + "', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {"
                + "      " + getShellString() + " 'echo " + getVariable("USERNAME") + ":" + getVariable("PASSWORD") + " > script'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.SUCCESS, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(password, b);
            FilePath script = story.j.jenkins.getWorkspaceFor(p).child("script");
            String log = script.readToString().trim();
            assertEquals(username + ":" + password, script.readToString().trim());
        });
    }

    @Test
    public void shouldFailIfMissingCredentials() {
        final String credentialsId = "cloudfoundry";
        final String token = "fakeToken";
        final String jobId = "testJob";
        story.then(r -> {
            VaultUsernamePasswordCredentialImpl c = new VaultUsernamePasswordCredentialImpl(
                null, credentialsId, "Test Credentials");
            c.setPath("secret/cloudfoundry");
            c.setUsernameKey(null);
            c.setPasswordKey(null);
            c.setEngineVersion(1);
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), c);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + " withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: '"
                + credentialsId
                + "', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) { "
                + "      " + getShellString() + " 'echo " + getVariable("USERNAME") + ":" + getVariable("PASSWORD") + " > script'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.FAILURE, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(token, b);
            story.j.assertLogContains("credentials", b);
        });
    }
}
