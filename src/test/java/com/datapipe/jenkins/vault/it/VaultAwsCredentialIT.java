package com.datapipe.jenkins.vault.it;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.common.VaultAwsCredential;
import com.datapipe.jenkins.vault.credentials.common.VaultAwsCredentialImpl;
import hudson.FilePath;
import hudson.model.Result;
import hudson.util.Secret;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getShellString;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getVariable;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class VaultAwsCredentialIT {

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    @Test
    public void shouldRetrieveCorrectCredentialsFromVault() throws Exception {
        final String credentialsId = "cid1";
        final String secret = "S3CR3T";
        final String jobId = "testJob";

        VaultAwsCredential up = mock(VaultAwsCredential.class);
        when(up.getId()).thenReturn(credentialsId);
        when(up.getSecret()).thenReturn(Secret.fromString(secret));
        CredentialsProvider.lookupStores(jenkins.getInstance()).iterator().next()
                .addCredentials(Domain.global(), up);
        WorkflowJob p = jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(
                new CpsFlowDefinition(""
                        + "node {\n"
                        + " withCredentials([[$class: 'VaultAwsCredentialBinding', credentialsId: '"
                        + credentialsId
                        + "', variable: 'SECRET']]) { "
                        + "      " + getShellString() + " 'echo " + getVariable("SECRET")
                        + " > secret.txt'\n"
                        + "  }\n"
                        + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        jenkins.assertBuildStatus(Result.SUCCESS, jenkins.waitForCompletion(b));
        jenkins.assertLogNotContains(secret, b);
        FilePath script = jenkins.getInstance().getWorkspaceFor(p).child("secret.txt");
        assertEquals(secret, script.readToString().trim());
    }

    @Test
    public void shouldFailIfMissingCredentials() throws Exception {
        final String credentialsId = "cid1";
        VaultAwsCredentialImpl c = new VaultAwsCredentialImpl(
                null, credentialsId, "Test Credentials");
        c.setEngineVersion(1);
        CredentialsProvider.lookupStores(jenkins).iterator().next()
                .addCredentials(Domain.global(), c);
        WorkflowJob p = jenkins.createProject(WorkflowJob.class, "testJob");
        p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + " withCredentials([[$class: 'VaultAwsCredentialBinding', credentialsId: '"
                + credentialsId
                + "', variable: 'SECRET']]) { "
                + "      " + getShellString() + " 'echo " + getVariable("SECRET") + "'\n"
                + "  }\n"
                + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        jenkins.assertBuildStatus(Result.FAILURE, jenkins.waitForCompletion(b));
        jenkins.assertLogContains("Exception", b);
    }
}
