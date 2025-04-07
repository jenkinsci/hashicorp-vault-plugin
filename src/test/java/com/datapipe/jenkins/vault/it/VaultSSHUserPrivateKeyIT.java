package com.datapipe.jenkins.vault.it;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.common.VaultSSHUserPrivateKey;
import com.datapipe.jenkins.vault.credentials.common.VaultSSHUserPrivateKeyImpl;
import hudson.FilePath;
import hudson.model.Result;
import hudson.model.Run;
import hudson.util.Secret;
import java.util.Collections;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getCatString;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getShellString;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getVariable;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@WithJenkins
class VaultSSHUserPrivateKeyIT {

    @Test
    void shouldRetrieveCorrectCredentialsFromVault(JenkinsRule j) throws Exception {
        final String credentialsId = "cloudfoundry";
        final String username = "luke";
        final String privateKey = "-----BEGIN RSA PRIVATE KEY-----\nmay the force be with you\n-----END RSA PRIVATE KEY-----";
        final String passphrase = "skywalker";
        final String jobId = "testJob";

        VaultSSHUserPrivateKey up = mock(
            VaultSSHUserPrivateKeyImpl.class);
        when(up.forRun(any(Run.class))).thenReturn(up);
        when(up.getId()).thenReturn(credentialsId);
        when(up.getUsername()).thenReturn(username);
        when(up.getPrivateKey()).thenReturn(privateKey);
        when(up.getPrivateKeys()).thenReturn(Collections.singletonList(privateKey));
        when(up.getPassphrase()).thenReturn(Secret.fromString(passphrase));
        CredentialsProvider.lookupStores(j.jenkins).iterator().next()
            .addCredentials(Domain.global(), up);
        WorkflowJob p = j.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + " withCredentials([sshUserPrivateKey(credentialsId: '" + credentialsId + "', usernameVariable: 'USERNAME', passphraseVariable: 'PASSPHRASE', keyFileVariable: 'SSH_KEY')]) { "
            + "      " + getShellString() + " 'echo " + getVariable("USERNAME") + ":" + getVariable("PASSPHRASE") + " > script'\n"
            + "      " + getShellString() + " '" + getCatString() + " \"" + getVariable("SSH_KEY") + "\" > private_key'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        j.assertBuildStatus(Result.SUCCESS, j.waitForCompletion(b));
        j.assertLogNotContains(passphrase, b);
        FilePath script = j.jenkins.getWorkspaceFor(p).child("script");
        assertEquals(username + ":" + passphrase, script.readToString().trim());
        FilePath key = j.jenkins.getWorkspaceFor(p).child("private_key");
        assertEquals(privateKey, key.readToString().trim());
    }

    @Test
    void shouldRetrieveCorrectCredentialsFromVaultWithCustomKeys(JenkinsRule j) throws Exception {
        final String credentialsId = "custom";
        final String username = "luke";
        final String privateKey = "-----BEGIN RSA PRIVATE KEY-----\nmay the force be with you\n-----END RSA PRIVATE KEY-----";
        final String passphrase = "skywalker";
        final String jobId = "testJob";

        VaultSSHUserPrivateKeyImpl vup = new VaultSSHUserPrivateKeyImpl(
            null, credentialsId, "Test Credentials");
        vup.setPath("secret/custom");
        vup.setUsernameKey("name");
        vup.setPrivateKeyKey("key");
        vup.setPassphraseKey("secret");
        vup.setEngineVersion(1);

        VaultSSHUserPrivateKeyImpl vup_spy = spy(vup);
        doReturn(credentialsId).when(vup_spy).getId();
        doReturn(username).when(vup_spy).getUsername();
        doReturn(privateKey).when(vup_spy).getPrivateKey();
        doReturn(Secret.fromString(passphrase)).when(vup_spy).getPassphrase();
        CredentialsProvider.lookupStores(j.jenkins).iterator().next()
            .addCredentials(Domain.global(), vup_spy);
        WorkflowJob p = j.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + " withCredentials([sshUserPrivateKey(credentialsId: '" + credentialsId + "', usernameVariable: 'USERNAME', passphraseVariable: 'PASSPHRASE', keyFileVariable: 'SSH_KEY')]) { "
            + "      " + getShellString() + " 'echo " + getVariable("USERNAME") + ":" + getVariable("PASSPHRASE") + " > script'\n"
            + "      " + getShellString() + " '" + getCatString() + " \"" + getVariable("SSH_KEY") + "\" > private_key'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        j.assertBuildStatus(Result.SUCCESS, j.waitForCompletion(b));
        j.assertLogNotContains(passphrase, b);
        FilePath script = j.jenkins.getWorkspaceFor(p).child("script");
        String log = script.readToString().trim();
        assertEquals(username + ":" + passphrase, script.readToString().trim());
        FilePath key = j.jenkins.getWorkspaceFor(p).child("private_key");
        assertEquals(privateKey, key.readToString().trim());
    }

    @Test
    void shouldFailIfMissingCredentials(JenkinsRule j) throws Exception {
        final String credentialsId = "cloudfoundry";
        final String token = "fakeToken";
        final String jobId = "testJob";

        VaultSSHUserPrivateKeyImpl c = new VaultSSHUserPrivateKeyImpl(
            null, credentialsId, "Test Credentials");
        c.setPath("secret/cloudfoundry");
        c.setUsernameKey(null);
        c.setPrivateKeyKey(null);
        c.setPassphraseKey(null);
        c.setEngineVersion(1);
        CredentialsProvider.lookupStores(j.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);
        WorkflowJob p = j.jenkins.createProject(WorkflowJob.class, jobId);
        p.setDefinition(new CpsFlowDefinition(""
            + "node {\n"
            + " withCredentials([sshUserPrivateKey(credentialsId: '" + credentialsId + "', usernameVariable: 'USERNAME', passphraseVariable: 'PASSPHRASE', keyFileVariable: 'SSH_KEY')]) { "
            + "      " + getShellString() + " 'echo " + getVariable("USERNAME") + ":" + getVariable("PASSPHRASE") + " > script'\n"
            + "      " + getShellString() + " '" + getCatString() + " \"" + getVariable("SSH_KEY") + "\" > private_key'\n"
            + "  }\n"
            + "}", true));
        WorkflowRun b = p.scheduleBuild2(0).waitForStart();
        j.assertBuildStatus(Result.FAILURE, j.waitForCompletion(b));
        j.assertLogNotContains(token, b);
        j.assertLogContains("credentials", b);
    }
}
