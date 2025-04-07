package com.datapipe.jenkins.vault.it.buildwrapper;

import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.util.TestConstants;
import com.datapipe.jenkins.vault.util.VaultContainer;
import hudson.model.Result;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.IOUtils;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static com.datapipe.jenkins.vault.util.VaultTestUtil.hasDockerDaemon;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@WithJenkins
@Testcontainers(disabledWithoutDocker = true)
class CustomCredentialTest {
    @Container
    private static final VaultContainer container = VaultContainer.createVaultContainer();

    private static JenkinsRule j;

    private static WorkflowJob pipeline;

    @BeforeAll
    static void setupClass(JenkinsRule rule) throws Exception {
        j = rule;

        assumeTrue(hasDockerDaemon());
        container.initAndUnsealVault();
        container.setBasicSecrets();

        pipeline = j.createProject(WorkflowJob.class, "Pipeline");
        String pipelineText = IOUtils.toString(TestConstants.class.getResourceAsStream("custom_credential.groovy"), StandardCharsets.UTF_8);
        pipelineText = pipelineText.replaceAll("#VAULT_TOKEN#", container.getRootToken());
        pipeline.setDefinition(new CpsFlowDefinition(pipelineText, false));
    }

    @Test
    void CustomCredentialTestOK() throws Exception {
        GlobalVaultConfiguration globalVaultConfiguration = GlobalVaultConfiguration.get();
        VaultConfiguration vaultConfiguration = new VaultConfiguration();
        vaultConfiguration.setVaultUrl(container.getAddress());
        vaultConfiguration.setTimeout(1);
        vaultConfiguration.setEngineVersion(1);
        vaultConfiguration.setSkipSslVerification(true);
        globalVaultConfiguration.setConfiguration(vaultConfiguration);

        WorkflowRun build = pipeline.scheduleBuild2(0).get();

        j.assertBuildStatus(Result.SUCCESS, build);
        j.assertLogContains("****", build);
    }

}
