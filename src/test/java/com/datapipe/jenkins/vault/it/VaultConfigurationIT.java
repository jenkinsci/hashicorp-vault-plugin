package com.datapipe.jenkins.vault.it;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.VaultBuildWrapper;
import com.datapipe.jenkins.vault.configuration.FolderVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultAppRoleCredential;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import com.datapipe.jenkins.vault.model.VaultSecret;
import com.datapipe.jenkins.vault.model.VaultSecretValue;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Result;
import hudson.tasks.BatchFile;
import hudson.tasks.CommandInterpreter;
import hudson.tasks.Shell;
import hudson.util.Secret;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jenkinsci.plugins.workflow.actions.ArgumentsAction;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.flow.FlowExecution;
import org.jenkinsci.plugins.workflow.graph.FlowNode;
import org.jenkinsci.plugins.workflow.graphanalysis.DepthFirstScanner;
import org.jenkinsci.plugins.workflow.graphanalysis.NodeStepTypePredicate;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static com.datapipe.jenkins.vault.util.TestConstants.GLOBAL_CREDENTIALS_ID_1;
import static com.datapipe.jenkins.vault.util.TestConstants.GLOBAL_CREDENTIALS_ID_2;
import static com.datapipe.jenkins.vault.util.TestConstants.GLOBAL_ENGINE_VERSION_2;
import static com.datapipe.jenkins.vault.util.TestConstants.JENKINSFILE_URL;
import static com.datapipe.jenkins.vault.util.TestConstants.TIMEOUT;
import static hudson.Functions.isWindows;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@WithJenkins
public class VaultConfigurationIT {

    private JenkinsRule jenkins;

    private Credentials GLOBAL_CREDENTIAL_1;
    private Credentials GLOBAL_CREDENTIAL_2;

    private FreeStyleProject project;

    @BeforeEach
    void setupJenkins(JenkinsRule rule) throws Exception {
        jenkins = rule;
        GlobalVaultConfiguration globalConfig = GlobalVaultConfiguration.get();
        assertThat(globalConfig, is(notNullValue()));
        VaultConfiguration vaultConfig = new VaultConfiguration();
        vaultConfig.setVaultUrl("http://global-vault-url.com");
        vaultConfig.setVaultCredentialId(GLOBAL_CREDENTIALS_ID_1);
        vaultConfig.setFailIfNotFound(false);
        vaultConfig.setEngineVersion(GLOBAL_ENGINE_VERSION_2);
        vaultConfig.setVaultNamespace("mynamespace");
        vaultConfig.setTimeout(TIMEOUT);
        globalConfig.setConfiguration(vaultConfig);

        globalConfig.save();

        GLOBAL_CREDENTIAL_1 = createTokenCredential(GLOBAL_CREDENTIALS_ID_1);
        GLOBAL_CREDENTIAL_2 = createTokenCredential(GLOBAL_CREDENTIALS_ID_2);

        SystemCredentialsProvider.getInstance()
            .setDomainCredentialsMap(Collections.singletonMap(Domain.global(), Arrays
                .asList(GLOBAL_CREDENTIAL_1, GLOBAL_CREDENTIAL_2)));

        this.project = jenkins.createFreeStyleProject("test");
    }

    private VaultAccessor mockVaultAccessor(Integer engineVersion) {
        VaultAccessor vaultAccessor = mock(VaultAccessor.class);
        Map<String, String> returnValue = new HashMap<>();
        returnValue.put("key1", "some-secret");
        LogicalResponse resp = mock(LogicalResponse.class);
        RestResponse rest = mock(RestResponse.class);
        when(resp.getData()).thenReturn(returnValue);
        when(resp.getRestResponse()).thenReturn(rest);
        when(rest.getStatus()).thenReturn(200);
        when(vaultAccessor.read("secret/path1", engineVersion)).thenReturn(resp);
        return vaultAccessor;
    }

    private List<VaultSecret> standardSecrets() {
        List<VaultSecret> secrets = new ArrayList<>();
        VaultSecretValue secretValue = new VaultSecretValue("envVar1", "key1");
        List<VaultSecretValue> secretValues = new ArrayList<>();
        secretValues.add(secretValue);
        VaultSecret secret = new VaultSecret("secret/path1", secretValues);
        secret.setEngineVersion(2);
        secrets.add(secret);
        return secrets;
    }

    public static CommandInterpreter echoSecret() {
        CommandInterpreter command;
        if (isWindows()) {
            command = new BatchFile("echo %envVar1%");
        } else {
            command = new Shell("echo $envVar1");
        }
        return command;
    }

    public static String getShellString() {
        return isWindows() ? "bat" : "sh";
    }

    public static String getCatString() {
        return isWindows() ? "type" : "cat";
    }

    public static String getCopyString() {
        return isWindows() ? "copy" : "cp";
    }

    public static String getVariable(String v) {
        return isWindows() ? "%" + v + "%" : "$" + v;
    }

    private void assertOverridePolicies(String globalPolicies, Boolean globalDisableOverride, Boolean folderDisableOverride,
        String policiesResult) throws Exception {
        VaultConfiguration globalConfig = GlobalVaultConfiguration.get().getConfiguration();
        globalConfig.setPolicies(globalPolicies);
        globalConfig.setDisableChildPoliciesOverride(globalDisableOverride);

        Folder folder = jenkins.createProject(Folder.class, "sub1");
        VaultConfiguration folderConfig = new VaultConfiguration();
        folderConfig.setPolicies("folder-policies");
        folderConfig.setDisableChildPoliciesOverride(folderDisableOverride);
        folder.addProperty(new FolderVaultConfiguration(folderConfig));

        FreeStyleProject project = folder.createProject(FreeStyleProject.class, "test");
        FreeStyleBuild build = mock(FreeStyleBuild.class);
        when(build.getParent()).thenReturn(project);
        VaultConfiguration vaultConfig = new VaultConfiguration();
        vaultConfig.setPolicies("job-policies");

        assertThat(VaultAccessor.pullAndMergeConfiguration(build, vaultConfig).getPolicies(),
            equalTo(policiesResult));
    }

    private void assertOverridePolicies(Boolean globalDisableOverride, Boolean folderDisableOverride,
        String policiesResult) throws Exception {
        assertOverridePolicies("global-policies", globalDisableOverride, folderDisableOverride, policiesResult);
    }

    @Test
    void shouldUseGlobalConfiguration() throws Exception {
        List<VaultSecret> secrets = standardSecrets();

        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
        VaultAccessor mockAccessor = mockVaultAccessor(GLOBAL_ENGINE_VERSION_2);
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        this.project.getBuildWrappersList().add(vaultBuildWrapper);
        this.project.getBuildersList().add(echoSecret());

        FreeStyleBuild build = this.project.scheduleBuild2(0).get();
        assertThat(vaultBuildWrapper.getConfiguration().getVaultUrl(),
            is("http://global-vault-url.com"));
        assertThat(vaultBuildWrapper.getConfiguration().getVaultCredentialId(),
            is(GLOBAL_CREDENTIALS_ID_1));
        assertThat(vaultBuildWrapper.getConfiguration().getEngineVersion(),
            is(GLOBAL_ENGINE_VERSION_2));

        jenkins.assertBuildStatus(Result.SUCCESS, build);
        jenkins.assertLogContains("echo ****", build);
        jenkins.assertLogNotContains("some-secret", build);

        VaultConfig config = new VaultConfig().address("http://global-vault-url.com");
        mockAccessor.setConfig(config);
        mockAccessor.setCredential((VaultCredential) GLOBAL_CREDENTIAL_1);

        verify(mockAccessor, times(1)).init();
        verify(mockAccessor, times(1)).read("secret/path1", GLOBAL_ENGINE_VERSION_2);
    }

    @Test
    void shouldUseJobConfiguration() throws Exception {
        List<VaultSecret> secrets = standardSecrets();

        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
        VaultAccessor mockAccessor = mockVaultAccessor(GLOBAL_ENGINE_VERSION_2);
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        this.project.getBuildWrappersList().add(vaultBuildWrapper);
        VaultConfiguration vaultConfig = new VaultConfiguration();
        vaultConfig.setVaultUrl("http://job-vault-url.com");
        vaultConfig.setVaultCredentialId(GLOBAL_CREDENTIALS_ID_2);
        vaultConfig.setFailIfNotFound(false);
        vaultConfig.setEngineVersion(GLOBAL_ENGINE_VERSION_2);
        vaultConfig.setVaultNamespace("mynamespace");
        vaultConfig.setTimeout(TIMEOUT);
        vaultBuildWrapper.setConfiguration(vaultConfig);
        this.project.getBuildersList().add(echoSecret());

        FreeStyleBuild build = this.project.scheduleBuild2(0).get();

        assertThat(vaultBuildWrapper.getConfiguration().getVaultUrl(),
            is("http://job-vault-url.com"));
        assertThat(vaultBuildWrapper.getConfiguration().getVaultCredentialId(),
            is(GLOBAL_CREDENTIALS_ID_2));
        assertThat(vaultBuildWrapper.getConfiguration().getEngineVersion(),
            is(GLOBAL_ENGINE_VERSION_2));

        jenkins.assertBuildStatus(Result.SUCCESS, build);

        VaultConfig config = new VaultConfig().address("http://job-vault-url.com");
        mockAccessor.setConfig(config);
        mockAccessor.setCredential((VaultCredential) GLOBAL_CREDENTIAL_2);
        verify(mockAccessor, times(1)).init();
        verify(mockAccessor, times(1)).read("secret/path1", GLOBAL_ENGINE_VERSION_2);
        jenkins.assertLogContains("echo ****", build);
        jenkins.assertLogNotContains("some-secret", build);
        assertThat(VaultAccessor.pullAndMergeConfiguration(build, vaultConfig).getPolicies(), nullValue());
    }

    @Test
    void shouldUseJobConfigurationWithoutDisableOverrides() throws Exception {
        assertOverridePolicies(false, false, "job-policies");
    }

    @Test
    void shouldUseFolderConfigurationWithDisableOverrides() throws Exception {
        assertOverridePolicies(false, true, "folder-policies");
    }

    @Test
    void shouldUseGlobalConfigurationWithDisableOverrides() throws Exception {
        assertOverridePolicies(true, false, "global-policies");
    }

    @Test
    void shouldUseEmptyGlobalConfigurationWithDisableOverrides() throws Exception {
        assertOverridePolicies(null, true, true, null);
    }

    @Test
    void shouldDealWithTokenBasedCredential() throws Exception {
        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(standardSecrets());
        VaultAccessor mockAccessor = mockVaultAccessor(GLOBAL_ENGINE_VERSION_2);
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        VaultCredential credential = new VaultTokenCredential(CredentialsScope.GLOBAL, "token-1",
            "description", Secret.fromString("test-token"));
        SystemCredentialsProvider.getInstance().setDomainCredentialsMap(
            Collections.singletonMap(Domain.global(), Collections.singletonList(credential)));

        this.project.getBuildWrappersList().add(vaultBuildWrapper);

        VaultConfiguration vaultConfig = new VaultConfiguration();
        vaultConfig.setVaultUrl("http://job-vault-url.com");
        vaultConfig.setVaultCredentialId("token-1");
        vaultConfig.setFailIfNotFound(false);
        vaultConfig.setVaultNamespace("mynamespace");
        vaultConfig.setTimeout(TIMEOUT);
        vaultBuildWrapper.setConfiguration(vaultConfig);
        this.project.getBuildersList().add(echoSecret());

        FreeStyleBuild build = this.project.scheduleBuild2(0).get();

        assertThat(vaultBuildWrapper.getConfiguration().getVaultUrl(),
            is("http://job-vault-url.com"));
        assertThat(vaultBuildWrapper.getConfiguration().getVaultCredentialId(), is("token-1"));

        jenkins.assertBuildStatus(Result.SUCCESS, build);

        VaultConfig config = new VaultConfig().address("http://job-vault-url.com");
        mockAccessor.setConfig(config);
        mockAccessor.setCredential(credential);
        verify(mockAccessor, times(1)).init();
        verify(mockAccessor, times(1)).read("secret/path1", GLOBAL_ENGINE_VERSION_2);
        jenkins.assertLogContains("echo ****", build);
        jenkins.assertLogNotContains("some-secret", build);
    }

    @Test
    void shouldUseJenkinsfileConfiguration() throws Exception {
        WorkflowJob pipeline = jenkins.createProject(WorkflowJob.class, "Pipeline");
        pipeline.setDefinition(new CpsFlowDefinition("node {\n" +
            "    withVaultMock(\n" +
            "        configuration: [ \n" +
            "            vaultCredentialId: '" + GLOBAL_CREDENTIALS_ID_2 + "', \n" +
            "            vaultUrl: '" + JENKINSFILE_URL + "'], \n" +
            "        vaultSecrets: [\n" +
            "            [path: 'secret/path1', secretValues: [\n" +
            "                 [envVar: 'envVar1', vaultKey: 'key1']]]]) {\n" +
            "            " + getShellString() + " \"echo ${env.envVar1}\"\n" +
            "      }\n" +
            "}", true));

        WorkflowRun build = pipeline.scheduleBuild2(0).get();

        jenkins.assertBuildStatus(Result.SUCCESS, build);
        jenkins.assertLogContains("echo ****", build);
        jenkins.assertLogNotContains("some-secret", build);

        FlowExecution execution = build.getExecution();
        DepthFirstScanner scanner = new DepthFirstScanner();
        List<FlowNode> shellSteps = scanner.filteredNodes(execution, new NodeStepTypePredicate(getShellString()));
        assertThat(shellSteps, hasSize(1));
        assertThat(shellSteps.get(0).getAction(ArgumentsAction.class), is(notNullValue()));
        assertThat(shellSteps.get(0).getAction(ArgumentsAction.class).getArguments(), hasEntry("script", "echo ${envVar1}"));
    }

    @Test
    void shouldFailIfCredentialsNotConfigured() throws Exception {
        GlobalVaultConfiguration globalConfig = GlobalVaultConfiguration.get();
        assertThat(globalConfig, is(notNullValue()));
        VaultConfiguration vaultConfig = new VaultConfiguration();
        vaultConfig.setVaultUrl("http://global-vault-url.com");
        vaultConfig.setFailIfNotFound(false);
        vaultConfig.setVaultNamespace("mynamespace");
        vaultConfig.setTimeout(TIMEOUT);

        globalConfig.setConfiguration(vaultConfig);

        globalConfig.save();

        List<VaultSecret> secrets = standardSecrets();

        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
        VaultAccessor mockAccessor = mockVaultAccessor(GLOBAL_ENGINE_VERSION_2);
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        this.project.getBuildWrappersList().add(vaultBuildWrapper);
        this.project.getBuildersList().add(echoSecret());

        FreeStyleBuild build = this.project.scheduleBuild2(0).get();

        jenkins.assertBuildStatus(Result.FAILURE, build);
        VaultConfig config = new VaultConfig().address(anyString());
        mockAccessor.setConfig(config);
        mockAccessor.setCredential(any(VaultCredential.class));
        verify(mockAccessor, times(0)).init();
        verify(mockAccessor, times(0)).read(anyString(), anyInt());
        jenkins.assertLogContains(
            "The credential id was not configured - please specify the credentials to use.", build);
    }

    @Test
    void shouldFailIfUrlNotConfigured() throws Exception {
        GlobalVaultConfiguration globalConfig = GlobalVaultConfiguration.get();
        assertThat(globalConfig, is(notNullValue()));
        VaultConfiguration vaultConfig = new VaultConfiguration();
        vaultConfig.setVaultCredentialId(GLOBAL_CREDENTIALS_ID_2);
        vaultConfig.setFailIfNotFound(false);
        vaultConfig.setVaultNamespace("mynamespace");
        vaultConfig.setTimeout(TIMEOUT);
        globalConfig.setConfiguration(vaultConfig);

        globalConfig.save();

        List<VaultSecret> secrets = standardSecrets();

        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
        VaultAccessor mockAccessor = mockVaultAccessor(GLOBAL_ENGINE_VERSION_2);
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        this.project.getBuildWrappersList().add(vaultBuildWrapper);
        this.project.getBuildersList().add(echoSecret());

        FreeStyleBuild build = this.project.scheduleBuild2(0).get();

        jenkins.assertBuildStatus(Result.FAILURE, build);
        VaultConfig config = new VaultConfig().address(anyString());
        mockAccessor.setConfig(config);
        mockAccessor.setCredential(any(VaultCredential.class));

        verify(mockAccessor, times(0)).init();
        verify(mockAccessor, times(0)).read(anyString(), anyInt());
        jenkins.assertLogContains(
            "The vault url was not configured - please specify the vault url to use.", build);
    }

    @Test
    void shouldFailIfNoConfigurationExists() throws Exception {
        GlobalVaultConfiguration globalConfig = GlobalVaultConfiguration.get();
        assertThat(globalConfig, is(notNullValue()));
        globalConfig.setConfiguration(null);

        globalConfig.save();
        List<VaultSecret> secrets = standardSecrets();

        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
        VaultAccessor mockAccessor = mockVaultAccessor(GLOBAL_ENGINE_VERSION_2);
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        this.project.getBuildWrappersList().add(vaultBuildWrapper);
        this.project.getBuildersList().add(echoSecret());

        FreeStyleBuild build = this.project.scheduleBuild2(0).get();

        jenkins.assertBuildStatus(Result.FAILURE, build);
        VaultConfig config = new VaultConfig().address(anyString());
        mockAccessor.setConfig(config);
        mockAccessor.setCredential(any(VaultCredential.class));
        verify(mockAccessor, times(0)).init();
        verify(mockAccessor, times(0)).read(anyString(), anyInt());
        jenkins
            .assertLogContains("No configuration found - please configure the VaultPlugin.", build);
    }

    @Test
    void shouldFailIfCredentialsDoNotExist() throws Exception {
        GlobalVaultConfiguration globalConfig = GlobalVaultConfiguration.get();
        assertThat(globalConfig, is(notNullValue()));
        VaultConfiguration vaultConfig = new VaultConfiguration();
        vaultConfig.setVaultUrl("http://example.com");
        vaultConfig.setVaultCredentialId("some-made-up-ID");
        vaultConfig.setFailIfNotFound(false);
        vaultConfig.setVaultNamespace("mynamespace");
        vaultConfig.setTimeout(TIMEOUT);
        globalConfig.setConfiguration(vaultConfig);

        globalConfig.save();

        List<VaultSecret> secrets = standardSecrets();

        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
        VaultAccessor mockAccessor = mockVaultAccessor(GLOBAL_ENGINE_VERSION_2);
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        this.project.getBuildWrappersList().add(vaultBuildWrapper);
        this.project.getBuildersList().add(echoSecret());

        FreeStyleBuild build = this.project.scheduleBuild2(0).get();

        jenkins.assertBuildStatus(Result.FAILURE, build);
        VaultConfig config = new VaultConfig().address(anyString());
        mockAccessor.setConfig(config);
        mockAccessor.setCredential(any(VaultCredential.class));
        verify(mockAccessor, times(0)).init();
        verify(mockAccessor, times(0)).read(anyString(), anyInt());
        jenkins.assertLogContains("CredentialsUnavailableException", build);
    }

    public static VaultAppRoleCredential createTokenCredential(final String credentialId) {
        Vault vault = mock(Vault.class, withSettings().serializable());
        VaultAppRoleCredential cred = mock(VaultAppRoleCredential.class,
            withSettings().serializable());
        when(cred.getId()).thenReturn(credentialId);
        when(cred.getDescription()).thenReturn("description");
        when(cred.getRoleId()).thenReturn("role-id-" + credentialId);
        when(cred.getSecretId()).thenReturn(Secret.fromString("secret-id-" + credentialId));
        when(cred.authorizeWithVault(any(), eq(null))).thenReturn(vault);
        return cred;

    }
}
