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
import java.io.IOException;
import org.apache.commons.io.IOUtils;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class SSLErrorTest extends AbstractSSLTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void SSLError() throws Exception {
        String credentialsId = "vaultToken";
        VaultTokenCredential c = new VaultTokenCredential(CredentialsScope.GLOBAL,
            credentialsId, "fake description", Secret.fromString(container.getRootToken()));
        CredentialsProvider.lookupStores(j.jenkins).iterator().next()
            .addCredentials(Domain.global(), c);

        GlobalVaultConfiguration globalVaultConfiguration = GlobalVaultConfiguration.get();
        VaultConfiguration vaultConfiguration = new VaultConfiguration();
        vaultConfiguration.setVaultUrl(container.getAddress());
        vaultConfiguration.setVaultCredentialId(credentialsId);
        vaultConfiguration.setTimeout(1);
        globalVaultConfiguration.setConfiguration(vaultConfiguration);

        WorkflowJob pipeline = j.createProject(WorkflowJob.class, "Pipeline");
        String pipelineText =  IOUtils.toString(TestConstants.class.getResourceAsStream("pipeline.groovy"));
        pipeline.setDefinition(new CpsFlowDefinition(pipelineText, true));

        WorkflowRun build = pipeline.scheduleBuild2(0).get();

        j.assertBuildStatus(Result.FAILURE, build);
        j.assertLogContains("javax.net.ssl.SSLHandshakeException", build);
    }
}
