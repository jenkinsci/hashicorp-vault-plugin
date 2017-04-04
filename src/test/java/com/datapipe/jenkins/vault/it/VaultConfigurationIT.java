package com.datapipe.jenkins.vault.it;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

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
import hudson.tasks.Shell;
import hudson.util.Secret;
import jenkins.model.GlobalConfiguration;

public class FreeStyleJobIT {
   @Rule
   public JenkinsRule jenkins = new JenkinsRule();

   private static final String GLOBAL_CREDENTIALS_ID_1 = "global-1";
   private static final String GLOBAL_CREDENTIALS_ID_2 = "global-2";

   private FreeStyleProject project;

   @Before
   public void setupJenkins() throws IOException {
      GlobalVaultConfiguration globalConfig = GlobalConfiguration.all().get(GlobalVaultConfiguration.class);
      globalConfig.setConfiguration(new VaultConfiguration("http://vault-url.com", GLOBAL_CREDENTIALS_ID_1));

      globalConfig.save();

      SystemCredentialsProvider.getInstance().save();
      SystemCredentialsProvider.getInstance().setDomainCredentialsMap(
            Collections.singletonMap(Domain.global(), Arrays.asList(
                    createTokenCredential(GLOBAL_CREDENTIALS_ID_1),
                    createTokenCredential(GLOBAL_CREDENTIALS_ID_2))));
      this.project = jenkins.createFreeStyleProject("test");
   }

   private VaultAccessor mockVaultAccessor() {
      VaultAccessor vaultAccessor = mock(VaultAccessor.class);
      Map<String, String> returnValue = new HashMap<>();
      returnValue.put("key1", "some-secret");
      when(vaultAccessor.read("secret/path1")).thenReturn(returnValue);
      return vaultAccessor;
   }

   @Test
   public void shouldUseGlobalConfiguration() throws Exception {
      List<VaultSecret> secrets = new ArrayList<VaultSecret>();
      VaultSecretValue secretValue = new VaultSecretValue("envVar1", "key1");
      List<VaultSecretValue> secretValues = new ArrayList<VaultSecretValue>();
      secretValues.add(secretValue);

      secrets.add(new VaultSecret("secret/path1", secretValues));
      VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
      VaultAccessor mockAccessor = mockVaultAccessor();
      vaultBuildWrapper.setVaultAccessor(mockAccessor);

      this.project.getBuildWrappersList().add(vaultBuildWrapper);
      this.project.getBuildersList().add(new Shell("echo $envVar1"));

      FreeStyleBuild build = this.project.scheduleBuild2(0).get();
      assertThat(vaultBuildWrapper.getConfiguration().getVaultUrl(), is("http://vault-url.com"));
      assertThat(vaultBuildWrapper.getConfiguration().getVaultTokenCredentialId(), is(GLOBAL_CREDENTIALS_ID_1));

      jenkins.assertLogContains("echo ****", build);
      verify(mockAccessor, times(1)).auth("role-id", Secret.fromString("secret-id"));
      verify(mockAccessor, times(1)).read("secret/path1");
   }

   @Test
   public void shouldUseJenkinsfileConfiguration() throws Exception {
      List<VaultSecret> secrets = new ArrayList<VaultSecret>();
      VaultSecretValue secretValue = new VaultSecretValue("envVar1", "key1");
      List<VaultSecretValue> secretValues = new ArrayList<VaultSecretValue>();
      secretValues.add(secretValue);

      secrets.add(new VaultSecret("secret/path1", secretValues));
      VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
      VaultAccessor mockAccessor = mockVaultAccessor();
      vaultBuildWrapper.setVaultAccessor(mockAccessor);
      // that's the interesting part:
      // this is as if one was setting the confgiuration directly in the
      // Jenkinsfile
      vaultBuildWrapper.setConfiguration(new VaultConfiguration("http://other-vault-url.com", GLOBAL_CREDENTIALS_ID_2));

      this.project.getBuildWrappersList().add(vaultBuildWrapper);
      this.project.getBuildersList().add(new Shell("echo $envVar1"));

      FreeStyleBuild build = this.project.scheduleBuild2(0).get();
      assertThat(vaultBuildWrapper.getConfiguration().getVaultUrl(), is("http://other-vault-url.com"));
      assertThat(vaultBuildWrapper.getConfiguration().getVaultTokenCredentialId(), is(GLOBAL_CREDENTIALS_ID_2));

      verify(mockAccessor, times(1)).auth("role-id", Secret.fromString("secret-id"));
      verify(mockAccessor, times(1)).read("secret/path1");
      jenkins.assertLogContains("echo ****", build);
   }

   private static Credentials createTokenCredential(final String credentialId) {
      return new VaultTokenCredential() {
         @Override
         public String getRoleId() {
            return "role-id";
         }

         @Override
         public Secret getSecretId() {
            return Secret.fromString("secret-id");
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
