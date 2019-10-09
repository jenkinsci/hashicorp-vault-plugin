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
import org.apache.commons.io.IOUtils;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class SSLSkipVerifyTest extends AbstractSSLTest implements TestConstants {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void SSLSkipVerify() throws Exception {
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
        vaultConfiguration.setSkipSslVerification(true);
        globalVaultConfiguration.setConfiguration(vaultConfiguration);

        WorkflowJob pipeline = j.createProject(WorkflowJob.class, "Pipeline");
        String pipelineText =  IOUtils.toString(TestConstants.class.getResourceAsStream("pipeline.groovy"));
        pipeline.setDefinition(new CpsFlowDefinition(pipelineText, true));

        WorkflowRun build = pipeline.scheduleBuild2(0).get();

        j.assertBuildStatus(Result.SUCCESS, build);
        j.assertLogContains("****", build);
    }
}
