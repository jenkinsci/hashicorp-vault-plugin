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
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.RestoreSystemProperties;
import org.junit.rules.TemporaryFolder;
import org.jvnet.hudson.test.JenkinsRule;

import static com.datapipe.jenkins.vault.util.VaultTestUtil.hasDockerDaemon;
import static org.junit.Assume.assumeTrue;

public class CustomCredentialTest implements TestConstants {
    @ClassRule
    public static VaultContainer container = VaultContainer.createVaultContainer();

    @ClassRule
    public static JenkinsRule j = new JenkinsRule();

    @Rule
    public final RestoreSystemProperties restoreSystemProperties = new RestoreSystemProperties();

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    private static WorkflowJob pipeline;

    @BeforeClass
    public static void setupClass() throws Exception {
        assumeTrue(hasDockerDaemon());
        container.initAndUnsealVault();
        container.setBasicSecrets();

        pipeline = j.createProject(WorkflowJob.class, "Pipeline");
        String pipelineText = IOUtils.toString(TestConstants.class.getResourceAsStream("custom_credential.groovy"), StandardCharsets.UTF_8);
        pipelineText = pipelineText.replaceAll("#VAULT_TOKEN#", container.getRootToken());
        pipeline.setDefinition(new CpsFlowDefinition(pipelineText, false));
    }

    @Test
    public void CustomCredentialTestOK() throws Exception {
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
