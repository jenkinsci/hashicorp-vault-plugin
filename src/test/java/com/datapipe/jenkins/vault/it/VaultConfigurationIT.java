package com.datapipe.jenkins.vault.it;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.response.LogicalResponse;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.VaultBuildWrapper;
import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultAppRoleCredential;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
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
import hudson.util.Secret;
import jenkins.model.GlobalConfiguration;

public class VaultConfigurationIT {
   @Rule
   public JenkinsRule jenkins = new JenkinsRule();

   public static final String GLOBAL_CREDENTIALS_ID_1 = "global-1";
   public static final String GLOBAL_CREDENTIALS_ID_2 = "global-2";

   private Credentials GLOBAL_CREDENTIAL_1;
   private Credentials GLOBAL_CREDENTIAL_2;

   public static final String JENKINSFILE_URL = "http://jenkinsfile-vault-url.com";

   private FreeStyleProject project;

   @Before
   public void setupJenkins() throws IOException {
      GlobalVaultConfiguration globalConfig = GlobalConfiguration.all().get(GlobalVaultConfiguration.class);
      globalConfig.setConfiguration(new VaultConfiguration("http://global-vault-url.com", GLOBAL_CREDENTIALS_ID_1, false));

      globalConfig.save();


      GLOBAL_CREDENTIAL_1 = createTokenCredential(GLOBAL_CREDENTIALS_ID_1);
      GLOBAL_CREDENTIAL_2 = createTokenCredential(GLOBAL_CREDENTIALS_ID_2);

      SystemCredentialsProvider.getInstance().setDomainCredentialsMap(Collections.singletonMap(Domain.global(), Arrays
            .asList(GLOBAL_CREDENTIAL_1, GLOBAL_CREDENTIAL_2)));

      this.project = jenkins.createFreeStyleProject("test");
   }

   private VaultAccessor mockVaultAccessor() {
      VaultAccessor vaultAccessor = mock(VaultAccessor.class);
      Map<String, String> returnValue = new HashMap<>();
      returnValue.put("key1", "some-secret");
      LogicalResponse resp = mock(LogicalResponse.class);
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
   public void shouldUseGlobalConfiguration() throws Exception {
      List<VaultSecret> secrets = standardSecrets();

      VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
      VaultAccessor mockAccessor = mockVaultAccessor();
      vaultBuildWrapper.setVaultAccessor(mockAccessor);

      this.project.getBuildWrappersList().add(vaultBuildWrapper);
      this.project.getBuildersList().add(new Shell("echo $envVar1"));

      FreeStyleBuild build = this.project.scheduleBuild2(0).get();
      assertThat(vaultBuildWrapper.getConfiguration().getVaultUrl(), is("http://global-vault-url.com"));
      assertThat(vaultBuildWrapper.getConfiguration().getVaultCredentialId(), is(GLOBAL_CREDENTIALS_ID_1));

      jenkins.assertBuildStatus(Result.SUCCESS, build);
      jenkins.assertLogContains("echo ****", build);
      jenkins.assertLogNotContains("some-secret", build);
      verify(mockAccessor, times(1)).init("http://global-vault-url.com", (VaultCredential) GLOBAL_CREDENTIAL_1, false);
      verify(mockAccessor, times(1)).read("secret/path1", 2);
   }

    @Test
    public void shouldUseJobConfiguration() throws Exception {
       List<VaultSecret> secrets = standardSecrets();

        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
        VaultAccessor mockAccessor = mockVaultAccessor();
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        this.project.getBuildWrappersList().add(vaultBuildWrapper);
        vaultBuildWrapper.setConfiguration(new VaultConfiguration("http://job-vault-url.com", GLOBAL_CREDENTIALS_ID_2, false));
        this.project.getBuildersList().add(new Shell("echo $envVar1"));

        FreeStyleBuild build = this.project.scheduleBuild2(0).get();

        assertThat(vaultBuildWrapper.getConfiguration().getVaultUrl(), is("http://job-vault-url.com"));
        assertThat(vaultBuildWrapper.getConfiguration().getVaultCredentialId(), is(GLOBAL_CREDENTIALS_ID_2));

        jenkins.assertBuildStatus(Result.SUCCESS, build);
        verify(mockAccessor, times(1)).init("http://job-vault-url.com", (VaultCredential) GLOBAL_CREDENTIAL_2, false);
        verify(mockAccessor, times(1)).read("secret/path1", 2);
        jenkins.assertLogContains("echo ****", build);
        jenkins.assertLogNotContains("some-secret", build);
    }

    @Test
    public void shouldDealWithTokenBasedCredential() throws Exception {
      VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(standardSecrets());
       VaultAccessor mockAccessor = mockVaultAccessor();
       vaultBuildWrapper.setVaultAccessor(mockAccessor);

       Credentials credential = new VaultTokenCredential(CredentialsScope.GLOBAL, "token-1", "description", Secret.fromString("test-token"));
       SystemCredentialsProvider.getInstance().setDomainCredentialsMap(Collections.singletonMap(Domain.global(),Arrays.asList(credential)));

       this.project.getBuildWrappersList().add(vaultBuildWrapper);
       vaultBuildWrapper.setConfiguration(new VaultConfiguration("http://job-vault-url.com", "token-1", false));
       this.project.getBuildersList().add(new Shell("echo $envVar1"));

       FreeStyleBuild build = this.project.scheduleBuild2(0).get();

       assertThat(vaultBuildWrapper.getConfiguration().getVaultUrl(), is("http://job-vault-url.com"));
       assertThat(vaultBuildWrapper.getConfiguration().getVaultCredentialId(), is("token-1"));

       jenkins.assertBuildStatus(Result.SUCCESS, build);
       verify(mockAccessor, times(1)).init("http://job-vault-url.com", (VaultCredential) credential, false);
       verify(mockAccessor, times(1)).read("secret/path1", 2);
       jenkins.assertLogContains("echo ****", build);
       jenkins.assertLogNotContains("some-secret", build);
    }

   @Test
   public void shouldUseJenkinsfileConfiguration() throws Exception {
      WorkflowJob pipeline = jenkins.createProject(WorkflowJob.class, "Pipeline");
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
      jenkins.assertLogNotContains("some-secret", build);
   }

   @Test
   public void shouldFailIfCredentialsNotConfigured() throws Exception {
      GlobalVaultConfiguration globalConfig = GlobalConfiguration.all().get(GlobalVaultConfiguration.class);
      globalConfig.setConfiguration(new VaultConfiguration("http://global-vault-url.com", null, false));

      globalConfig.save();

      List<VaultSecret> secrets = standardSecrets();

      VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
      VaultAccessor mockAccessor = mockVaultAccessor();
      vaultBuildWrapper.setVaultAccessor(mockAccessor);

      this.project.getBuildWrappersList().add(vaultBuildWrapper);
      this.project.getBuildersList().add(new Shell("echo $envVar1"));

      FreeStyleBuild build = this.project.scheduleBuild2(0).get();

      jenkins.assertBuildStatus(Result.FAILURE, build);
      verify(mockAccessor, times(0)).init(anyString(), any(VaultCredential.class));
      verify(mockAccessor, times(0)).read(anyString(), anyInt());
      jenkins.assertLogContains("The credential id was not configured - please specify the credentials to use.", build);
   }

   @Test
   public void shouldFailIfUrlNotConfigured() throws Exception {
      GlobalVaultConfiguration globalConfig = GlobalConfiguration.all().get(GlobalVaultConfiguration.class);
      globalConfig.setConfiguration(new VaultConfiguration(null, GLOBAL_CREDENTIALS_ID_2, false));

      globalConfig.save();

      List<VaultSecret> secrets = standardSecrets();

      VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
      VaultAccessor mockAccessor = mockVaultAccessor();
      vaultBuildWrapper.setVaultAccessor(mockAccessor);

      this.project.getBuildWrappersList().add(vaultBuildWrapper);
      this.project.getBuildersList().add(new Shell("echo $envVar1"));

      FreeStyleBuild build = this.project.scheduleBuild2(0).get();

      jenkins.assertBuildStatus(Result.FAILURE, build);
      verify(mockAccessor, times(0)).init(anyString(), any(VaultCredential.class));
      verify(mockAccessor, times(0)).read(anyString(), anyInt());
      jenkins.assertLogContains("The vault url was not configured - please specify the vault url to use.", build);
   }

   @Test
   public void shouldFailIfNoConfigurationExists() throws Exception {
      GlobalVaultConfiguration globalConfig = GlobalConfiguration.all().get(GlobalVaultConfiguration.class);
      globalConfig.setConfiguration(null);

      globalConfig.save();
      List<VaultSecret> secrets = standardSecrets();

      VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
      VaultAccessor mockAccessor = mockVaultAccessor();
      vaultBuildWrapper.setVaultAccessor(mockAccessor);

      this.project.getBuildWrappersList().add(vaultBuildWrapper);
      this.project.getBuildersList().add(new Shell("echo $envVar1"));

      FreeStyleBuild build = this.project.scheduleBuild2(0).get();

      jenkins.assertBuildStatus(Result.FAILURE, build);
      verify(mockAccessor, times(0)).init(anyString(), any(VaultCredential.class));
      verify(mockAccessor, times(0)).read(anyString(), anyInt());
      jenkins.assertLogContains("No configuration found - please configure the VaultPlugin.", build);
   }

   @Test
   public void shouldFailIfCredentialsDoNotExist() throws Exception {
      GlobalVaultConfiguration globalConfig = GlobalConfiguration.all().get(GlobalVaultConfiguration.class);
      globalConfig.setConfiguration(new VaultConfiguration("http://example.com", "some-made-up-ID", false));

      globalConfig.save();

      List<VaultSecret> secrets = standardSecrets();

      VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
      VaultAccessor mockAccessor = mockVaultAccessor();
      vaultBuildWrapper.setVaultAccessor(mockAccessor);

      this.project.getBuildWrappersList().add(vaultBuildWrapper);
      this.project.getBuildersList().add(new Shell("echo $envVar1"));

      FreeStyleBuild build = this.project.scheduleBuild2(0).get();

      jenkins.assertBuildStatus(Result.FAILURE, build);
      verify(mockAccessor, times(0)).init(anyString(), any(VaultCredential.class));
      verify(mockAccessor, times(0)).read(anyString(), anyInt());
      jenkins.assertLogContains("CredentialsUnavailableException", build);
   }

   public static VaultAppRoleCredential createTokenCredential(final String credentialId) {
       Vault vault = mock(Vault.class, withSettings().serializable());
       VaultAppRoleCredential cred = mock(VaultAppRoleCredential.class, withSettings().serializable());
       when(cred.getId()).thenReturn(credentialId);
       when(cred.getDescription()).thenReturn("description");
       when(cred.getRoleId()).thenReturn("role-id-" + credentialId);
       when(cred.getSecretId()).thenReturn(Secret.fromString("secret-id-" + credentialId));
       when(cred.authorizeWithVault(any())).thenReturn(vault);
       return cred;

   }
}
