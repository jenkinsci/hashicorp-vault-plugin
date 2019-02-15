package com.datapipe.jenkins.vault.it.folder;

import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.GLOBAL_CREDENTIALS_ID_1;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.GLOBAL_CREDENTIALS_ID_2;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.JENKINSFILE_URL;
import static com.datapipe.jenkins.vault.it.VaultConfigurationIT.createTokenCredential;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bettercloud.vault.response.LogicalResponse;
import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.properties.FolderCredentialsProvider;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.domains.DomainCredentials;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.VaultBuildWrapper;
import com.datapipe.jenkins.vault.configuration.FolderVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.model.VaultSecret;
import com.datapipe.jenkins.vault.model.VaultSecretValue;

import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Result;
import hudson.tasks.Shell;
import jenkins.model.GlobalConfiguration;

public class FolderIT {
    // check that you cannot access another credentials folder
    // check that folder configuration takes precedence over global config
    // check that jenkinsfile config takes precedence over folder config (we could actually take a pipeline here - see config-file-provider-plugin

    private static final String FOLDER_1_CREDENTIALS_ID = "folder1";
    private static final String FOLDER_2_CREDENTIALS_ID = "folder2";

    private Credentials GLOBAL_CREDENTIAL_1;
    private Credentials GLOBAL_CREDENTIAL_2;

    private Credentials FOLDER_1_CREDENTIAL;
    private Credentials FOLDER_2_CREDENTIAL;

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    private FreeStyleProject projectInFolder1;
    private FreeStyleProject projectInFolder2;
    private Folder folder1;
    private Folder folder2;

    @Before
    public void setupJenkins() throws IOException {
        GlobalVaultConfiguration globalConfig = GlobalConfiguration.all().get(GlobalVaultConfiguration.class);
        globalConfig.setConfiguration(new VaultConfiguration("http://global-vault-url.com", GLOBAL_CREDENTIALS_ID_1, false));
        globalConfig.save();

        FOLDER_1_CREDENTIAL = createTokenCredential(FOLDER_1_CREDENTIALS_ID);
        FOLDER_2_CREDENTIAL = createTokenCredential(FOLDER_2_CREDENTIALS_ID);

        FolderCredentialsProvider.FolderCredentialsProperty folder1CredProperty = new FolderCredentialsProvider.FolderCredentialsProperty(
                new DomainCredentials[]{new DomainCredentials(Domain.global(), Arrays.asList(FOLDER_1_CREDENTIAL))});

        FolderCredentialsProvider.FolderCredentialsProperty folder2CredProperty = new FolderCredentialsProvider.FolderCredentialsProperty(
                new DomainCredentials[]{new DomainCredentials(Domain.global(), Arrays.asList(FOLDER_2_CREDENTIAL))});

        GLOBAL_CREDENTIAL_1 = createTokenCredential(GLOBAL_CREDENTIALS_ID_1);
        GLOBAL_CREDENTIAL_2 = createTokenCredential(GLOBAL_CREDENTIALS_ID_2);

        SystemCredentialsProvider.getInstance().setDomainCredentialsMap(Collections.singletonMap(Domain.global(), Arrays
                .asList(GLOBAL_CREDENTIAL_1, GLOBAL_CREDENTIAL_2)));

        this.folder1 = jenkins.createProject(Folder.class, "folder1");
        this.folder2 = jenkins.createProject(Folder.class, "folder2");

        folder1.addProperty(folder1CredProperty);
        folder2.addProperty(folder2CredProperty);

        projectInFolder1 = this.folder1.createProject(FreeStyleProject.class, "projectInFolder1");
        projectInFolder2 = this.folder2.createProject(FreeStyleProject.class, "projectInFolder2");
    }

    private VaultAccessor mockVaultAccessor() {
        VaultAccessor vaultAccessor = mock(VaultAccessor.class);
        LogicalResponse resp = mock(LogicalResponse.class);
        Map<String, String> returnValue = new HashMap<>();
        returnValue.put("key1", "some-secret");
        when(resp.getData()).thenReturn(returnValue);
        when(vaultAccessor.read("secret/path1", 2)).thenReturn(resp);
        return vaultAccessor;
    }

    private List<VaultSecret> standardSecrets(){
        List<VaultSecret> secrets = new ArrayList<VaultSecret>();
        VaultSecretValue secretValue = new VaultSecretValue("envVar1", "key1");
        List<VaultSecretValue> secretValues = new ArrayList<VaultSecretValue>();
        secretValues.add(secretValue);
        VaultSecret secret = new VaultSecret("secret/path1", secretValues);
        secret.setEngineVersion(2);
        secrets.add(secret);
        return secrets;
    }

    @Test
    public void folderShouldOverwriteGlobal() throws Exception {
        List<VaultSecret> secrets = standardSecrets();

        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
        VaultAccessor mockAccessor = mockVaultAccessor();
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        this.folder1.addProperty(new FolderVaultConfiguration(new VaultConfiguration("http://folder1.com", FOLDER_1_CREDENTIALS_ID, false)));

        this.projectInFolder1.getBuildWrappersList().add(vaultBuildWrapper);
        this.projectInFolder1.getBuildersList().add(new Shell("echo $envVar1"));

        FreeStyleBuild build = this.projectInFolder1.scheduleBuild2(0).get();
        assertThat(vaultBuildWrapper.getConfiguration().getVaultUrl(), is("http://folder1.com"));
        assertThat(vaultBuildWrapper.getConfiguration().getVaultCredentialId(), is(FOLDER_1_CREDENTIALS_ID));
        assertThat(vaultBuildWrapper.getConfiguration().isFailIfNotFound(), is(false));

        jenkins.assertBuildStatus(Result.SUCCESS, build);
        jenkins.assertLogContains("echo ****", build);
        verify(mockAccessor, times(1)).init("http://folder1.com", (VaultCredential) FOLDER_1_CREDENTIAL, false);
        verify(mockAccessor, times(1)).read("secret/path1", 2);
    }

    @Test
    public void jobInFolderShouldBeAbleToAccessCredentialsScopedToTheFolder() throws Exception {
        List<VaultSecret> secrets = standardSecrets();

        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
        VaultAccessor mockAccessor = mockVaultAccessor();
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        this.folder1.addProperty(new FolderVaultConfiguration(new VaultConfiguration("http://folder1.com", FOLDER_1_CREDENTIALS_ID, false)));

        this.projectInFolder1.getBuildWrappersList().add(vaultBuildWrapper);
        this.projectInFolder1.getBuildersList().add(new Shell("echo $envVar1"));

        FreeStyleBuild build = this.projectInFolder1.scheduleBuild2(0).get();
        verify(mockAccessor, times(1)).init("http://folder1.com", (VaultCredential)FOLDER_1_CREDENTIAL, false);
        assertThat(vaultBuildWrapper.getConfiguration().getVaultCredentialId(), is(FOLDER_1_CREDENTIALS_ID));
        assertThat(vaultBuildWrapper.getConfiguration().isFailIfNotFound(), is(false));

        jenkins.assertBuildStatus(Result.SUCCESS, build);
        jenkins.assertLogContains("echo ****", build);
        verify(mockAccessor, times(1)).init("http://folder1.com", (VaultCredential) FOLDER_1_CREDENTIAL, false);
        verify(mockAccessor, times(1)).read("secret/path1", 2);
    }

    @Test
    public void jobInFolderShouldNotBeAbleToAccessCredentialsScopedToAnotherFolder() throws Exception {
        List<VaultSecret> secrets = standardSecrets();

        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
        VaultAccessor mockAccessor = mockVaultAccessor();
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        this.folder1.addProperty(new FolderVaultConfiguration(new VaultConfiguration("http://folder1.com", FOLDER_2_CREDENTIALS_ID, false)));

        this.projectInFolder1.getBuildWrappersList().add(vaultBuildWrapper);
        this.projectInFolder1.getBuildersList().add(new Shell("echo $envVar1"));

        FreeStyleBuild build = this.projectInFolder1.scheduleBuild2(0).get();
        assertThat(vaultBuildWrapper.getConfiguration().getVaultUrl(), is("http://folder1.com"));
        assertThat(vaultBuildWrapper.getConfiguration().getVaultCredentialId(), is(FOLDER_2_CREDENTIALS_ID));
        assertThat(vaultBuildWrapper.getConfiguration().isFailIfNotFound(), is(false));

        jenkins.assertBuildStatus(Result.FAILURE, build);
        jenkins.assertLogContains("CredentialsUnavailableException", build);
        verify(mockAccessor, times(0)).init(anyString(), any(VaultCredential.class));
        verify(mockAccessor, times(0)).read(anyString(), anyInt());
    }

    @Test
    public void jenkinsfileShouldOverrideFolderConfig() throws Exception {
        WorkflowJob pipeline = folder1.createProject(WorkflowJob.class, "Pipeline");
        pipeline.setDefinition(new CpsFlowDefinition("node {\n" +
                "    wrap([$class: 'VaultBuildWrapperWithMockAccessor', \n" +
                "                   configuration: [$class: 'VaultConfiguration', \n" +
                "                             vaultCredentialId: '"+GLOBAL_CREDENTIALS_ID_2+"', \n" +
                "                             vaultUrl: '"+JENKINSFILE_URL+"'], \n" +
                "                   vaultSecrets: [\n" +
                "                            [$class: 'VaultSecret', path: 'secret/path1', secretValues: [\n" +
                "                            [$class: 'VaultSecretValue', envVar: 'envVar1', vaultKey: 'key1']]]]]) {\n" +
                "            sh \"echo ${env.envVar1}\"\n" +
                "      }\n" +
                "}", true));

        WorkflowRun build = pipeline.scheduleBuild2(0).get();

        jenkins.assertBuildStatus(Result.SUCCESS, build);
        jenkins.assertLogContains("echo ****", build);
    }

}
