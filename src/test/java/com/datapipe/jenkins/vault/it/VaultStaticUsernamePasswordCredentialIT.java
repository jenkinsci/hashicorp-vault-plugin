package com.datapipe.jenkins.vault.it;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.common.VaultStaticUsernamePasswordCredential;
import com.datapipe.jenkins.vault.credentials.common.VaultStaticUsernamePasswordCredentialImpl;
import hudson.FilePath;
import hudson.model.Result;
import hudson.model.Run;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

public class VaultStaticUsernamePasswordCredentialIT {

    @Rule
    public RestartableJenkinsRule story = new RestartableJenkinsRule();

    @Test
    public void shouldRetrievePasswordFromVaultWithStaticUsername() {
        final String credentialsId = "staticUsernameCredential";
        final String username = "static-user";
        final String password = "vaultPassword";
        final String jobId = "testJob";
        story.then(r -> {
            VaultStaticUsernamePasswordCredential credential = mock(
                VaultStaticUsernamePasswordCredentialImpl.class);
            when(credential.forRun(any(Run.class))).thenReturn(credential);
            when(credential.getId()).thenReturn(credentialsId);
            when(credential.getUsername()).thenReturn(username);
            when(credential.getPassword()).thenReturn(Secret.fromString(password));
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), credential);
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
    public void shouldRetrievePasswordFromVaultWithCustomPasswordKey() {
        final String credentialsId = "customKeyCredential";
        final String username = "static-user";
        final String password = "vaultPassword";
        final String jobId = "testJob";
        story.then(r -> {
            VaultStaticUsernamePasswordCredentialImpl credential =
                new VaultStaticUsernamePasswordCredentialImpl(null, credentialsId, "Test Credentials");
            credential.setPath("secret/myapp");
            credential.setUsername(username);
            credential.setPasswordKey("secret");
            credential.setEngineVersion(1);

            VaultStaticUsernamePasswordCredentialImpl credentialSpy = spy(credential);
            doReturn(credentialsId).when(credentialSpy).getId();
            doReturn(username).when(credentialSpy).getUsername();
            doReturn(Secret.fromString(password)).when(credentialSpy).getPassword();
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), credentialSpy);
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
            assertEquals(username + ":" + password, script.readToString().trim());
        });
    }

    @Test
    public void shouldFailIfPasswordKeyMissingFromVault() {
        final String credentialsId = "missingKeyCredential";
        final String jobId = "testJob";
        story.then(r -> {
            VaultStaticUsernamePasswordCredentialImpl credential =
                new VaultStaticUsernamePasswordCredentialImpl(null, credentialsId, "Test Credentials");
            credential.setPath("secret/myapp");
            credential.setUsername("static-user");
            credential.setPasswordKey(null);
            credential.setEngineVersion(1);
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), credential);
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
            story.j.assertLogContains("credentials", b);
        });
    }
}
