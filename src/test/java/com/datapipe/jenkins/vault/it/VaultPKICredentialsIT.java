package com.datapipe.jenkins.vault.it;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.common.VaultPKICredentials;
import com.datapipe.jenkins.vault.credentials.common.VaultPKICredentialsImpl;
import hudson.model.Result;
import hudson.model.Run;
import hudson.util.Secret;
import java.io.InputStream;
import java.security.KeyStore;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getShellString;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.getVariable;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration tests for the Vault PKI secrets engine credential.
 *
 * <p>Vault interaction is mocked – these tests verify the Jenkins credential/binding plumbing
 * and do not require a running Vault server.</p>
 */
public class VaultPKICredentialsIT {

    /** Password for the pre-built test keystore bundled in the test resources. */
    private static final String KS_PASSWORD = "skywalker";

    @Rule
    public RestartableJenkinsRule story = new RestartableJenkinsRule();

    // ---- Standard certificate() binding ----------------------------------------

    @Test
    public void shouldExposeKeyStoreViaCertificateBinding() {
        final String credentialsId = "vault-pki-cert-test";
        story.then(r -> {
            KeyStore ks = loadTestKeyStore();

            VaultPKICredentials cred = mock(VaultPKICredentialsImpl.class);
            when(cred.forRun(any(Run.class))).thenReturn(cred);
            when(cred.getId()).thenReturn(credentialsId);
            when(cred.getKeyStore()).thenReturn(ks);
            when(cred.getPassword()).thenReturn(Secret.fromString(KS_PASSWORD));
            when(cred.getCertificatePem()).thenReturn("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----");
            when(cred.getPrivateKeyPem()).thenReturn("-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----");
            when(cred.getIssuingCaPem()).thenReturn("-----BEGIN CERTIFICATE-----\nfakeca\n-----END CERTIFICATE-----");

            CredentialsProvider.lookupStores(r.jenkins).iterator().next()
                .addCredentials(Domain.global(), cred);

            WorkflowJob job = r.jenkins.createProject(WorkflowJob.class, "pki-cert-binding-test");
            job.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + "  withCredentials([certificate(credentialsId: '" + credentialsId + "',"
                + "    keystoreVariable: 'KS', passwordVariable: 'KS_PASS')]) {\n"
                + "    " + getShellString() + " 'echo " + getVariable("KS_PASS") + " > pw.txt'\n"
                + "  }\n"
                + "}", true));

            WorkflowRun b = job.scheduleBuild2(0).waitForStart();
            r.assertBuildStatus(Result.SUCCESS, r.waitForCompletion(b));
            r.assertLogNotContains(KS_PASSWORD, b);

            String written = r.jenkins.getWorkspaceFor(job).child("pw.txt").readToString().trim();
            assertEquals(KS_PASSWORD, written);
        });
    }

    // ---- Dedicated vaultPKI() binding ------------------------------------------

    @Test
    public void shouldExposeIndividualPemFilesViaPkiBinding() {
        final String credentialsId = "vault-pki-pem-test";
        final String fakeCertPem =
            "-----BEGIN CERTIFICATE-----\nZmFrZWNlcnQ=\n-----END CERTIFICATE-----";
        final String fakeKeyPem =
            "-----BEGIN PRIVATE KEY-----\nZmFrZWtleQ==\n-----END PRIVATE KEY-----";
        final String fakeCaPem =
            "-----BEGIN CERTIFICATE-----\nZmFrZWNh\n-----END CERTIFICATE-----";

        story.then(r -> {
            KeyStore ks = loadTestKeyStore();

            VaultPKICredentials cred = mock(VaultPKICredentialsImpl.class);
            when(cred.forRun(any(Run.class))).thenReturn(cred);
            when(cred.getId()).thenReturn(credentialsId);
            when(cred.getCertificatePem()).thenReturn(fakeCertPem);
            when(cred.getPrivateKeyPem()).thenReturn(fakeKeyPem);
            when(cred.getIssuingCaPem()).thenReturn(fakeCaPem);
            when(cred.getKeyStore()).thenReturn(ks);
            when(cred.getPassword()).thenReturn(Secret.fromString(KS_PASSWORD));

            CredentialsProvider.lookupStores(r.jenkins).iterator().next()
                .addCredentials(Domain.global(), cred);

            WorkflowJob job = r.jenkins.createProject(WorkflowJob.class, "pki-pem-binding-test");
            job.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + "  withCredentials([vaultPKI(credentialsId: '" + credentialsId + "',"
                + "    certPemVariable: 'CERT_FILE',"
                + "    privateKeyPemVariable: 'KEY_FILE',"
                + "    caPemVariable: 'CA_FILE')]) {\n"
                + "    " + getShellString() + " 'test -f " + getVariable("CERT_FILE") + "'\n"
                + "    " + getShellString() + " 'test -f " + getVariable("KEY_FILE") + "'\n"
                + "    " + getShellString() + " 'test -f " + getVariable("CA_FILE") + "'\n"
                + "    " + getShellString() + " 'cat " + getVariable("CERT_FILE") + " > cert_out.txt'\n"
                + "  }\n"
                + "}", true));

            WorkflowRun b = job.scheduleBuild2(0).waitForStart();
            r.assertBuildStatus(Result.SUCCESS, r.waitForCompletion(b));

            String certOut = r.jenkins.getWorkspaceFor(job).child("cert_out.txt")
                .readToString().trim();
            assertTrue("cert_out.txt should contain the certificate PEM",
                certOut.contains("BEGIN CERTIFICATE"));
        });
    }

    // ---- Default variable names ------------------------------------------------

    @Test
    public void shouldUseDefaultVariableNamesWhenNotSpecified() {
        final String credentialsId = "vault-pki-defaults-test";
        final String fakeCertPem =
            "-----BEGIN CERTIFICATE-----\nZmFrZWNlcnQ=\n-----END CERTIFICATE-----";

        story.then(r -> {
            KeyStore ks = loadTestKeyStore();

            VaultPKICredentials cred = mock(VaultPKICredentialsImpl.class);
            when(cred.forRun(any(Run.class))).thenReturn(cred);
            when(cred.getId()).thenReturn(credentialsId);
            when(cred.getCertificatePem()).thenReturn(fakeCertPem);
            when(cred.getPrivateKeyPem()).thenReturn("-----BEGIN PRIVATE KEY-----\nZg==\n-----END PRIVATE KEY-----");
            when(cred.getIssuingCaPem()).thenReturn("-----BEGIN CERTIFICATE-----\nZg==\n-----END CERTIFICATE-----");
            when(cred.getKeyStore()).thenReturn(ks);
            when(cred.getPassword()).thenReturn(Secret.fromString(KS_PASSWORD));

            CredentialsProvider.lookupStores(r.jenkins).iterator().next()
                .addCredentials(Domain.global(), cred);

            WorkflowJob job = r.jenkins.createProject(WorkflowJob.class, "pki-defaults-test");
            // Use default variable names (no explicit variable configuration)
            job.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + "  withCredentials([vaultPKI(credentialsId: '" + credentialsId + "')]) {\n"
                + "    " + getShellString() + " 'test -f " + getVariable("VAULT_PKI_CERT") + "'\n"
                + "    " + getShellString() + " 'test -f " + getVariable("VAULT_PKI_KEY") + "'\n"
                + "    " + getShellString() + " 'test -f " + getVariable("VAULT_PKI_CA") + "'\n"
                + "  }\n"
                + "}", true));

            WorkflowRun b = job.scheduleBuild2(0).waitForStart();
            r.assertBuildStatus(Result.SUCCESS, r.waitForCompletion(b));
        });
    }

    // ---- Missing pkiRole validation --------------------------------------------

    @Test
    public void shouldFailIfPkiRoleIsBlank() {
        final String credentialsId = "vault-pki-no-role";
        story.then(r -> {
            VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(null, credentialsId,
                "PKI credential with no role");
            cred.setPkiMount("pki");
            cred.setCommonName("jenkins.example.com");
            cred.setTtl("1h");
            // pkiRole intentionally not set

            CredentialsProvider.lookupStores(r.jenkins).iterator().next()
                .addCredentials(Domain.global(), cred);

            WorkflowJob job = r.jenkins.createProject(WorkflowJob.class, "pki-no-role-test");
            job.setDefinition(new CpsFlowDefinition(""
                + "node {\n"
                + "  withCredentials([certificate(credentialsId: '" + credentialsId + "',"
                + "    keystoreVariable: 'KS', passwordVariable: 'KP')]) {\n"
                + "    echo 'should not reach here'\n"
                + "  }\n"
                + "}", true));

            WorkflowRun b = job.scheduleBuild2(0).waitForStart();
            r.assertBuildStatus(Result.FAILURE, r.waitForCompletion(b));
        });
    }

    // ---- helpers ---------------------------------------------------------------

    private KeyStore loadTestKeyStore() {
        try {
            InputStream stream = getClass().getClassLoader().getResourceAsStream(
                "com/datapipe/jenkins/vault/it/keystore.pfx");
            assert stream != null;
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(stream, KS_PASSWORD.toCharArray());
            return ks;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load test keystore", e);
        }
    }
}
