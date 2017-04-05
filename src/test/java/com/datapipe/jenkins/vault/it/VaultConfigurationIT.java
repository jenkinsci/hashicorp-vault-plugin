package com.datapipe.jenkins.vault.it;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.VaultBuildWrapper;
import com.datapipe.jenkins.vault.configuration.GlobalVaultConfiguration;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredentialImpl;
import com.datapipe.jenkins.vault.model.VaultSecret;
import com.datapipe.jenkins.vault.model.VaultSecretValue;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Result;
import hudson.tasks.Shell;
import hudson.util.Secret;
import jenkins.model.GlobalConfiguration;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;
import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.*;

public class VaultConfigurationIT {
   @Rule
   public JenkinsRule jenkins = new JenkinsRule();

   public static final String GLOBAL_CREDENTIALS_ID_1 = "global-1";
   public static final String GLOBAL_CREDENTIALS_ID_2 = "global-2";

   public static final String JENKINSFILE_URL = "http://jenkinsfile-vault-url.com";

   private FreeStyleProject project;

   @Before
   public void setupJenkins() throws IOException {
      GlobalVaultConfiguration globalConfig = GlobalConfiguration.all().get(GlobalVaultConfiguration.class);
      globalConfig.setConfiguration(new VaultConfiguration("http://global-vault-url.com", GLOBAL_CREDENTIALS_ID_1));

      globalConfig.save();

      SystemCredentialsProvider.getInstance().save();
      SystemCredentialsProvider.getInstance().setDomainCredentialsMap(Collections.singletonMap(Domain.global(), Arrays
            .asList(createTokenCredential(GLOBAL_CREDENTIALS_ID_1), createTokenCredential(GLOBAL_CREDENTIALS_ID_2))));
      this.project = jenkins.createFreeStyleProject("test");
   }

   private VaultAccessor mockVaultAccessor() {
      VaultAccessor vaultAccessor = mock(VaultAccessor.class);
      Map<String, String> returnValue = new HashMap<>();
      returnValue.put("key1", "some-secret");
      when(vaultAccessor.read("secret/path1")).thenReturn(returnValue);
      return vaultAccessor;
   }

   private List<VaultSecret> standardSecrets(){
      List<VaultSecret> secrets = new ArrayList<VaultSecret>();
      VaultSecretValue secretValue = new VaultSecretValue("envVar1", "key1");
      List<VaultSecretValue> secretValues = new ArrayList<VaultSecretValue>();
      secretValues.add(secretValue);
      secrets.add(new VaultSecret("secret/path1", secretValues));
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
      assertThat(vaultBuildWrapper.getConfiguration().getVaultTokenCredentialId(), is(GLOBAL_CREDENTIALS_ID_1));

      jenkins.assertBuildStatus(Result.SUCCESS, build);
      jenkins.assertLogContains("echo ****", build);
       verify(mockAccessor, times(1)).init("http://global-vault-url.com");
      verify(mockAccessor, times(1)).auth("role-id-"+GLOBAL_CREDENTIALS_ID_1, Secret.fromString("secret-id-"+GLOBAL_CREDENTIALS_ID_1));
      verify(mockAccessor, times(1)).read("secret/path1");
   }

    @Test
    public void shouldUseJobConfiguration() throws Exception {
       List<VaultSecret> secrets = standardSecrets();

        VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
        VaultAccessor mockAccessor = mockVaultAccessor();
        vaultBuildWrapper.setVaultAccessor(mockAccessor);

        this.project.getBuildWrappersList().add(vaultBuildWrapper);
        vaultBuildWrapper.setConfiguration(new VaultConfiguration("http://job-vault-url.com", GLOBAL_CREDENTIALS_ID_2));
        this.project.getBuildersList().add(new Shell("echo $envVar1"));

        FreeStyleBuild build = this.project.scheduleBuild2(0).get();

        assertThat(vaultBuildWrapper.getConfiguration().getVaultUrl(), is("http://job-vault-url.com"));
        assertThat(vaultBuildWrapper.getConfiguration().getVaultTokenCredentialId(), is(GLOBAL_CREDENTIALS_ID_2));

        jenkins.assertBuildStatus(Result.SUCCESS, build);
        verify(mockAccessor, times(1)).init("http://job-vault-url.com");
        verify(mockAccessor, times(1)).auth("role-id-"+GLOBAL_CREDENTIALS_ID_2, Secret.fromString("secret-id-"+GLOBAL_CREDENTIALS_ID_2));
        verify(mockAccessor, times(1)).read("secret/path1");
        jenkins.assertLogContains("echo ****", build);
    }

   @Test
   public void shouldUseJenkinsfileConfiguration() throws Exception {
      List<VaultSecret> secrets = standardSecrets();

      VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
      VaultAccessor mockAccessor = mockVaultAccessor();
      vaultBuildWrapper.setVaultAccessor(mockAccessor);
      vaultBuildWrapper.setConfiguration(new VaultConfiguration("", GLOBAL_CREDENTIALS_ID_2));

      WorkflowJob pipeline = jenkins.createProject(WorkflowJob.class, "Pipeline");
      pipeline.setDefinition(new CpsFlowDefinition("node {\n" +
              "    wrap([$class: 'VaultBuildWrapperWithMockAccessor', \n" +
              "                   configuration: [$class: 'VaultConfiguration', \n" +
              "                             vaultTokenCredentialId: '"+GLOBAL_CREDENTIALS_ID_2+"', \n" +
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

   private static Credentials createTokenCredential(final String credentialId) {
      return new VaultTokenCredential() {
         @Override
         public String getRoleId() {
            return "role-id-"+credentialId;
         }

         @Override
         public Secret getSecretId() {
            return Secret.fromString("secret-id-"+credentialId);
         }

         @Override
         public String getDescription() {
            return "description";
         }

         @Override
         public String getId() {
            return credentialId;
         }

         @Override
         public CredentialsScope getScope() {
            return CredentialsScope.SYSTEM;
         }

         @Override
         public CredentialsDescriptor getDescriptor() {
            return new VaultTokenCredentialImpl.DescriptorImpl();
         }
      };
   }
}