package com.datapipe.jenkins.vault.it.buildwrapper;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.VaultConfig;
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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.RestoreSystemProperties;
import org.junit.rules.TemporaryFolder;
import org.jvnet.hudson.test.JenkinsRule;
import org.mockito.Mockito;

import static org.junit.Assume.assumeTrue;
import static org.mockito.Mockito.when;

public class SSLTest implements TestConstants {

    public static VaultContainer container = new VaultContainer();

    @ClassRule
    public static JenkinsRule j = new JenkinsRule();

    @Rule
    public final RestoreSystemProperties restoreSystemProperties = new RestoreSystemProperties();

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    private static WorkflowJob pipeline;
    private static final String credentialsId = "vaultToken";

    @BeforeClass
    public static void setupClass() throws IOException, InterruptedException {
        assumeTrue(DOCKER_AVAILABLE);
        container.start();
        container.initAndUnsealVault();
        container.setBasicSecrets();

        pipeline = j.createProject(WorkflowJob.class, "Pipeline");
        String pipelineText =  IOUtils.toString(TestConstants.class.getResourceAsStream("pipeline.groovy"));
        pipeline.setDefinition(new CpsFlowDefinition(pipelineText, true));

        VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", Secret.fromString(container.getRootToken()));
        CredentialsProvider.lookupStores(j.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);
    }

    @Test
    public void SSLError() throws Exception {
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
    public void SSLOk() throws Exception {
        File store = testFolder.newFile("cacerts.keystore");
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
    public void SSLSkipVerify() throws Exception {
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
