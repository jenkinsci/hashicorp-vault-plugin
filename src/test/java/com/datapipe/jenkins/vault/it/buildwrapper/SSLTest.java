package com.datapipe.jenkins.vault.it.buildwrapper;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import com.datapipe.jenkins.vault.util.TestConstants;
import com.datapipe.jenkins.vault.util.VaultContainer;
import hudson.model.Result;
import hudson.util.Secret;
import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultConfig;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.mockito.Mockito;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static com.datapipe.jenkins.vault.util.TestConstants.CERT_PEMFILE;
import static com.datapipe.jenkins.vault.util.VaultTestUtil.hasDockerDaemon;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.when;

@WithJenkins
@Testcontainers(disabledWithoutDocker = true)
class SSLTest {

    @Container
    private static final VaultContainer container = VaultContainer.createVaultContainer();

    private static JenkinsRule j;

    @TempDir
    private File testFolder;

    private static WorkflowJob pipeline;
    private static final String credentialsId = "vaultToken";

    @BeforeAll
    static void setupClass(JenkinsRule rule) throws Exception {
        j = rule;
        assumeTrue(hasDockerDaemon());
        container.initAndUnsealVault();
        container.setBasicSecrets();

        pipeline = j.createProject(WorkflowJob.class, "Pipeline");
        String pipelineText =  IOUtils.toString(TestConstants.class.getResourceAsStream("pipeline.groovy"), StandardCharsets.UTF_8);
        pipeline.setDefinition(new CpsFlowDefinition(pipelineText, true));

        VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", Secret.fromString(container.getRootToken()));
        CredentialsProvider.lookupStores(j.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);
    }

    @Test
    void SSLError() throws Exception {
        GlobalVaultConfiguration globalVaultConfiguration = GlobalVaultConfiguration.get();
        VaultConfiguration vaultConfiguration = new VaultConfiguration();
        vaultConfiguration.setVaultUrl(container.getAddress());
        vaultConfiguration.setVaultCredentialId(credentialsId);
        vaultConfiguration.setTimeout(1);
        globalVaultConfiguration.setConfiguration(vaultConfiguration);

        WorkflowRun build = pipeline.scheduleBuild2(0).get();

        j.assertBuildStatus(Result.FAILURE, build);
        j.assertLogContains("javax.net.ssl.SSLHandshakeException", build);
    }

    @Test
    void SSLOk() throws Exception {
        File store = File.createTempFile("cacerts.keystore", null, testFolder);
        File certificate = new File(CERT_PEMFILE);
        createKeyStore(store, certificate);

        GlobalVaultConfiguration globalVaultConfiguration = GlobalVaultConfiguration.get();
        VaultConfiguration vaultConfiguration = Mockito.mock(VaultConfiguration.class);
        when(vaultConfiguration.getVaultUrl()).thenReturn(container.getAddress());
        when(vaultConfiguration.getVaultCredentialId()).thenReturn(credentialsId);
        when(vaultConfiguration.getEngineVersion()).thenReturn(1);
        when(vaultConfiguration.getTimeout()).thenReturn(5);
        globalVaultConfiguration.setConfiguration(vaultConfiguration);

        VaultConfig config = new VaultConfig()
            .address(vaultConfiguration.getVaultUrl())
            .engineVersion(vaultConfiguration.getEngineVersion())
            .sslConfig(new SslConfig()
                .trustStoreFile(store)
                .verify(true)
                .build()
            );
        when(vaultConfiguration.getVaultConfig()).thenReturn(config);

        WorkflowRun build = pipeline.scheduleBuild2(0).get();

        j.assertBuildStatus(Result.SUCCESS, build);
        j.assertLogContains("****", build);
    }

    @Test
    void SSLSkipVerify() throws Exception {
        GlobalVaultConfiguration globalVaultConfiguration = GlobalVaultConfiguration.get();
        VaultConfiguration vaultConfiguration = new VaultConfiguration();
        vaultConfiguration.setVaultUrl(container.getAddress());
        vaultConfiguration.setVaultCredentialId(credentialsId);
        vaultConfiguration.setEngineVersion(1);
        vaultConfiguration.setTimeout(5);
        vaultConfiguration.setSkipSslVerification(true);
        globalVaultConfiguration.setConfiguration(vaultConfiguration);

        WorkflowRun build = pipeline.scheduleBuild2(0).get();

        j.assertBuildStatus(Result.SUCCESS, build);
        j.assertLogContains("****", build);
    }

    private void createKeyStore(File store, File certificate) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(certificate);
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        is.close();
        keyStore.load(null, null);
        keyStore.setCertificateEntry("dockerCert", cer);
        try (FileOutputStream o = new FileOutputStream(store)) {
            keyStore.store(o, "changeit".toCharArray());
        }
    }
}
