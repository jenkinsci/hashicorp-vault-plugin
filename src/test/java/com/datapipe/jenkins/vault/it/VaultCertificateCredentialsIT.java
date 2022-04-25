package com.datapipe.jenkins.vault.it;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.common.VaultCertificateCredentials;
import com.datapipe.jenkins.vault.credentials.common.VaultCertificateCredentialsImpl;
import hudson.FilePath;
import hudson.model.Result;
import hudson.util.Secret;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Collections;
import java.util.List;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getCopyString;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getShellString;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getVariable;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class VaultCertificateCredentialsIT {

    @Rule
    public RestartableJenkinsRule story = new RestartableJenkinsRule();

    @Test
    public void shouldRetrieveCorrectCredentialsFromVault() {
        final String credentialsId = "cloudfoundry";
        final String password = "skywalker";
        final KeyStore keyStore = loadKeyStore(loadKeyStoreAsInputStream(), password);
        final String jobId = "testJob";
        story.then(r -> {
            VaultCertificateCredentials up = mock(
                VaultCertificateCredentialsImpl.class);
            when(up.getId()).thenReturn(credentialsId);
            when(up.getKeyStore()).thenReturn(keyStore);
            when(up.getPassword()).thenReturn(Secret.fromString(password));
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), up);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + " withCredentials([certificate(credentialsId: '" + credentialsId + "', passwordVariable: 'PASSWORD', keystoreVariable: 'KEYSTORE')]) { "
                + "      " + getShellString() + " 'echo " + getVariable("PASSWORD") + " > script'\n"
                + "      " + getShellString() + " '" + getCopyString() + " \"" + getVariable("KEYSTORE") + "\" keystore'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.SUCCESS, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(password, b);
            FilePath script = story.j.jenkins.getWorkspaceFor(p).child("script");
            assertEquals(password, script.readToString().trim());
            FilePath ks = story.j.jenkins.getWorkspaceFor(p).child("keystore");
            KeyStore actualKeyStore = loadKeyStore(ks.read(), password);
            assertKeyStoreEquals(keyStore, actualKeyStore);
        });
    }

    @Test
    public void shouldRetrieveCorrectCredentialsFromVaultWithCustomKeys() {
        final String credentialsId = "custom";
        final String password = "skywalker";
        final KeyStore keyStore = loadKeyStore(loadKeyStoreAsInputStream(), password);
        final String jobId = "testJob";
        story.then(r -> {
            VaultCertificateCredentialsImpl vup = new VaultCertificateCredentialsImpl(
                null, credentialsId, "Test Credentials");
            vup.setPath("secret/custom");
            vup.setKeyStoreKey("key");
            vup.setPasswordKey("secret");
            vup.setEngineVersion(1);

            VaultCertificateCredentialsImpl vup_spy = spy(vup);
            doReturn(credentialsId).when(vup_spy).getId();
            doReturn(keyStore).when(vup_spy).getKeyStore();
            doReturn(Secret.fromString(password)).when(vup_spy).getPassword();
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), vup_spy);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + " withCredentials([certificate(credentialsId: '" + credentialsId + "', passwordVariable: 'PASSWORD', keystoreVariable: 'KEYSTORE')]) { "
                + "      " + getShellString() + " 'echo " + getVariable("PASSWORD") + " > script'\n"
                + "      " + getShellString() + " '" + getCopyString() + " \"" + getVariable("KEYSTORE") + "\" keystore'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.SUCCESS, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(password, b);
            FilePath script = story.j.jenkins.getWorkspaceFor(p).child("script");
            String log = script.readToString().trim();
            assertEquals(password, script.readToString().trim());
            FilePath ks = story.j.jenkins.getWorkspaceFor(p).child("keystore");
            KeyStore actualKeyStore = loadKeyStore(ks.read(), password);
            assertKeyStoreEquals(keyStore, actualKeyStore);
        });
    }

    @Test
    public void shouldFailIfMissingCredentials() {
        final String credentialsId = "cloudfoundry";
        final String token = "fakeToken";
        final String jobId = "testJob";
        story.then(r -> {
            VaultCertificateCredentialsImpl c = new VaultCertificateCredentialsImpl(
                null, credentialsId, "Test Credentials");
            c.setPath("secret/cloudfoundry");
            c.setKeyStoreKey(null);
            c.setPasswordKey(null);
            c.setEngineVersion(1);
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next()
                .addCredentials(Domain.global(), c);
            WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, jobId);
            p.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + " withCredentials([certificate(credentialsId: '" + credentialsId + "', passwordVariable: 'PASSWORD', keystoreVariable: 'KEYSTORE')]) { "
                + "      " + getShellString() + " 'echo " + getVariable("PASSWORD") + " > script'\n"
                + "      " + getShellString() + " '" + getCopyString() + " \"" + getVariable("KEYSTORE") + "\" keystore'\n"
                + "  }\n"
                + "}", true));
            WorkflowRun b = p.scheduleBuild2(0).waitForStart();
            story.j.assertBuildStatus(Result.FAILURE, story.j.waitForCompletion(b));
            story.j.assertLogNotContains(token, b);
            story.j.assertLogContains("credentials", b);
        });
    }

    private InputStream loadKeyStoreAsInputStream() {
        InputStream stream = getClass().getClassLoader().getResourceAsStream("com/datapipe/jenkins/vault/it/keystore.pfx");
        assert stream != null;
        return stream;
    }

    private KeyStore loadKeyStore(InputStream in, String password) {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(loadKeyStoreAsInputStream(), password.toCharArray());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return keyStore;
    }

    private static void assertKeyStoreEquals(KeyStore expected, KeyStore actual) {
        try {
            List<String> expectedAliases = Collections.list(expected.aliases());
            List<String> actualAliases = Collections.list(actual.aliases());
            assertEquals(expectedAliases, actualAliases);
            for (String alias : expectedAliases) {
                assertTrue(actual.containsAlias(alias));
                assertEquals(expected.getCertificate(alias), actual.getCertificate(alias));
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
