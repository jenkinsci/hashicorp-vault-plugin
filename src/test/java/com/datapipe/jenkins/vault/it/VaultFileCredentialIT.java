package com.datapipe.jenkins.vault.it;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.common.VaultFileCredential;
import com.datapipe.jenkins.vault.credentials.common.VaultFileCredentialImpl;
import hudson.FilePath;
import hudson.model.Result;
import hudson.model.Run;
import java.io.ByteArrayInputStream;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getShellString;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getVariable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class VaultFileCredentialIT {

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    @Test
    public void shouldRetrieveCorrectCredentialsFromVault() throws Exception {
        final String credentialsId = "cid1";
        final String fileName = "S3CR3T";
        final String jobId = "testJob";

        VaultFileCredential up = mock(VaultFileCredential.class);
        when(up.forRun(any(Run.class))).thenReturn(up);
        when(up.getId()).thenReturn(credentialsId);
        when(up.getContent()).thenReturn(new ByteArrayInputStream("fake".getBytes()));
        when(up.getFileName()).thenReturn(fileName);
        CredentialsProvider.lookupStores(jenkins.getInstance()).iterator().next()
            .addCredentials(Domain.global(), up);
        WorkflowJob p = jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(
            new CpsFlowDefinition(""
                + "node {\n"
                + " withCredentials([[$class: 'VaultFileCredentialBinding', credentialsId: '"
                + credentialsId
                + "', variable: 'SECRET']]) { "
                + "      " + getShellString() + " 'echo " + getVariable("SECRET")
                + " > secret.txt'\n"
                + "  }\n"
                + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        jenkins.assertBuildStatus(Result.SUCCESS, jenkins.waitForCompletion(b));
        jenkins.assertLogNotContains(fileName, b);
        FilePath script = jenkins.getInstance().getWorkspaceFor(p).child("secret.txt");
        assert(script.readToString().trim().endsWith(fileName));
    }

    @Test
    public void shouldFailIfMissingCredentials() throws Exception {
        final String credentialsId = "cid1";
        VaultFileCredentialImpl c = new VaultFileCredentialImpl(
            null, credentialsId, "Test Credentials");
        c.setEngineVersion(1);
        CredentialsProvider.lookupStores(jenkins).iterator().next()
            .addCredentials(Domain.global(), c);
        WorkflowJob p = jenkins.createProject(WorkflowJob.class, "testJob");
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + " withCredentials([[$class: 'VaultFileCredentialBinding', credentialsId: '"
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
