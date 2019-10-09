package com.datapipe.jenkins.vault.it.buildwrapper;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import com.datapipe.jenkins.vault.util.TestConstants;
import hudson.model.Result;
import hudson.util.Secret;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.RestoreSystemProperties;
import org.junit.rules.TemporaryFolder;
import org.jvnet.hudson.test.JenkinsRule;

public class SSLOkTest extends AbstractSSLTest implements TestConstants {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Rule
    public final RestoreSystemProperties restoreSystemProperties = new RestoreSystemProperties();

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Test
    public void SSLOk() throws Exception {
        File store = testFolder.newFile("cacerts.keystore");
        File certificate = new File(CERT_PEMFILE);
        createKeyStore(store, certificate);

        System.setProperty("javax.net.ssl.trustStore", store.getAbsolutePath());

        String credentialsId = "vaultToken";
        VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", Secret.fromString(container.getRootToken()));
        CredentialsProvider.lookupStores(j.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);

        GlobalVaultConfiguration globalVaultConfiguration = GlobalVaultConfiguration.get();
        VaultConfiguration vaultConfiguration = new VaultConfiguration();
        vaultConfiguration.setVaultUrl(container.getAddress());
        vaultConfiguration.setVaultCredentialId(credentialsId);
        vaultConfiguration.setEngineVersion(1);
        vaultConfiguration.setTimeout(5);
        globalVaultConfiguration.setConfiguration(vaultConfiguration);

        WorkflowJob pipeline = j.createProject(WorkflowJob.class, "Pipeline");
        String pipelineText =  IOUtils.toString(TestConstants.class.getResourceAsStream("pipeline.groovy"));
        pipeline.setDefinition(new CpsFlowDefinition(pipelineText, true));

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
