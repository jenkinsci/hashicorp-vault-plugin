package com.datapipe.jenkins.vault.it;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.common.VaultStringCredential;
import com.datapipe.jenkins.vault.credentials.common.VaultStringCredentialImpl;
import hudson.FilePath;
import hudson.model.Result;
import hudson.util.Secret;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runners.model.Statement;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getShellString;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getVariable;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class VaultStringCredentialIT {

    @Rule
    public RestartableJenkinsRule story = new RestartableJenkinsRule();

    @Test
    public void shouldRetrieveCorrectCredentialsFromVault() {
        final String credentialsId = "cid1";
        final String secret = "S3CR3T";
        final String jobId = "testJob";
        story.addStep(new Statement() {
            @Override
            public void evaluate() throws Throwable {
                VaultStringCredential up = mock(VaultStringCredential.class);
                when(up.getId()).thenReturn(credentialsId);
                when(up.getSecret()).thenReturn(Secret.fromString(secret));
                CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                    .addCredentials(Domain.global(), up);
                WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
                p.setDefinition(
                    new CpsFlowDefinition(""
                        + "node {\n"
                        + " withCredentials([[$class: 'VaultStringCredentialBinding', credentialsId: '"
                        + credentialsId
                        + "', variable: 'SECRET']]) { "
                        + "      " + getShellString() + " 'echo " + getVariable("SECRET") + " > secret.txt'\n"
                        + "  }\n"
                        + "}", true));
                WorkflowRun b = p.scheduleBuild2(0).waitForStart();
                story.j.assertBuildStatus(Result.SUCCESS, story.j.waitForCompletion(b));
                story.j.assertLogNotContains(secret, b);
                FilePath script = story.j.jenkins.getWorkspaceFor(p).child("secret.txt");
                assertEquals(secret, script.readToString().trim());
            }
        });
    }

    @Test
    public void shouldFailIfMissingCredentials() {
        story.addStep(new Statement() {
            @Override
            public void evaluate() throws Throwable {
                final String credentialsId = "cid1";
                VaultStringCredentialImpl c = new VaultStringCredentialImpl(
                    null, credentialsId, "Test Credentials");
                c.setEngineVersion(1);
                CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                    .addCredentials(Domain.global(), c);
                WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, "testJob");
                p.setDefinition(new CpsFlowDefinition(""
                    + "node {\n"
                    + " withCredentials([[$class: 'VaultStringCredentialBinding', credentialsId: '"
                    + credentialsId
                    + "', variable: 'SECRET']]) { "
                    + "      " + getShellString() + " 'echo " + getVariable("SECRET") + "'\n"
                    + "  }\n"
                    + "}", true));
                WorkflowRun b = p.scheduleBuild2(0).waitForStart();
                story.j.assertBuildStatus(Result.FAILURE, story.j.waitForCompletion(b));
                story.j.assertLogContains("Exception", b);
            }
        });
    }
}
