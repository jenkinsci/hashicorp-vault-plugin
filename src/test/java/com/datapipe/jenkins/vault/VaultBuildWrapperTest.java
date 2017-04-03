package com.datapipe.jenkins.vault;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import com.datapipe.jenkins.vault.credentials.impl.VaultTokenCredentialImpl;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.tasks.Shell;
import hudson.util.Secret;
import org.apache.commons.io.FileUtils;
import org.junit.*;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ExecutionException;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

/**
 * These test cases make use of the Jenkins test harness. It requires the VAULT_ADDR and VAULT_TOKEN
 * environment variables be set with a vault server listening on VAULT_ADDR
 * 
 * @author Peter Tierno
 */
public class VaultBuildWrapperTest {

  /**
   * The URL to the vault server (eg. <code>http://127.0.0.1:8200</code>)
   */
  private static final String VAULT_ADDR = System.getenv("VAULT_ADDR");

  /**
   * The authentication token to authenticate against the vault server with.
   */
  private static final String VAULT_TOKEN = System.getenv("VAULT_TOKEN");

  private static final String VAULT_TOKEN_CREDENTIAL_ID = "token-credential";

  private static Vault vault;

  @Rule
  public JenkinsRule jenkins = new JenkinsRule();

  private FreeStyleProject project;

  /**
   * Creates the static {@link com.bettercloud.vault.Vault} client and writes the test secrets
   * before any test cases are ran.
   * 
   * @throws VaultException
   */
  @BeforeClass
  public static void init() throws VaultException, IOException {
    vault = new Vault(new VaultConfig(VAULT_ADDR, VAULT_TOKEN));
    writeTestSecrets();
  }

  @Before
  public void setupCredentials() throws IOException {
    SystemCredentialsProvider.getInstance().save();
    SystemCredentialsProvider.getInstance().setDomainCredentialsMap(Collections.singletonMap(Domain.global(), createTokenCredential()));
  }

  private static List<Credentials> createTokenCredential(){
    return Arrays.asList(new Credentials[]{new VaultTokenCredential() {
      @Override
      public Secret getToken() {
        return Secret.fromString(VAULT_TOKEN);
      }

      @NonNull
      @Override
      public String getDescription() {
        return "description";
      }

      @NonNull
      @Override
      public String getId() {
        return VAULT_TOKEN_CREDENTIAL_ID;
      }

      @Override
      public CredentialsScope getScope() {
        return CredentialsScope.SYSTEM;
      }

      @NonNull
      @Override
      public CredentialsDescriptor getDescriptor() {
        return new VaultTokenCredentialImpl.DescriptorImpl();
      }
    }});
  }

  /**
   * Deletes the vault secrets after all test cases are ran.
   * 
   * @throws VaultException
   */
  @AfterClass
  public static void destroy() throws VaultException {
    deleteTestSecrets();
  }

  /**
   * Creates the test project in Jenkins.
   * 
   * @throws Exception
   */
  @Before
  public void setUp() throws Exception {
    this.project = jenkins.createFreeStyleProject("test");
  }

  /**
   * Tests the {@link VaultBuildWrapper} against a single {@link VaultSecret}
   * 
   * @throws ExecutionException
   * @throws InterruptedException
   * @throws IOException
   */
  @Test
  public void testSingleSecret()
      throws ExecutionException, InterruptedException, IOException {

    List<VaultSecret> secrets = new ArrayList<VaultSecret>();
    VaultSecretValue secretValue = new VaultSecretValue("envVar1", "key1");
    List<VaultSecretValue> secretValues = new ArrayList<VaultSecretValue>();
    secretValues.add(secretValue);
    secrets.add(new VaultSecret("secret/path1", secretValues));

    VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
    vaultBuildWrapper.setVaultUrl(VaultBuildWrapperTest.VAULT_ADDR);
    vaultBuildWrapper.setAuthTokenCredentialId(VaultBuildWrapperTest.VAULT_TOKEN_CREDENTIAL_ID);

    this.project.getBuildWrappersList().add(vaultBuildWrapper);
    this.project.getBuildersList().add(new Shell("echo $envVar1"));

    FreeStyleBuild build = this.project.scheduleBuild2(0).get();

    String log = FileUtils.readFileToString(build.getLogFile());

    assertThat(log, containsString("+ echo ****"));
    assertThat(log, not(containsString("+ echo value1")));

  }

  /**
   * Tests the {@link VaultBuildWrapper} against multiple {@link VaultSecret}'s
   *
   * @throws ExecutionException
   * @throws InterruptedException
   * @throws IOException
   */
  @Test
  public void testMultipleSecrets()
      throws ExecutionException, InterruptedException, IOException {

    List<VaultSecret> secrets = new ArrayList<VaultSecret>();

    for (int i = 1; i <= 10; i++) {
      VaultSecretValue secretValue =
          new VaultSecretValue("envVar" + i, "key" + i);
      List<VaultSecretValue> secretValues = new ArrayList<VaultSecretValue>();
      secretValues.add(secretValue);
      secrets.add(new VaultSecret("secret/path" + i, secretValues));
    }

    VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
    vaultBuildWrapper.setVaultUrl(VaultBuildWrapperTest.VAULT_ADDR);
    vaultBuildWrapper.setAuthTokenCredentialId(VaultBuildWrapperTest.VAULT_TOKEN_CREDENTIAL_ID);

    this.project.getBuildWrappersList().add(vaultBuildWrapper);

    for (int i = 1; i <= 10; i++) {
      this.project.getBuildersList().add(new Shell("echo $envVar" + i));
    }

    FreeStyleBuild build = this.project.scheduleBuild2(0).get();
    String log = FileUtils.readFileToString(build.getLogFile());

    for (int i = 1; i <= 10; i++) {
      assertThat(log, not(containsString("echo value" + i)));
    }
    // count number of occurences as of http://stackoverflow.com/a/770069
    assertThat(log.split("\\+ echo \\*\\*\\*\\*", -1).length - 1, is(10));
  }

  /**
   * Utility method to create the test secrets in the vault.
   *
   * @throws VaultException
   */
  private static void writeTestSecrets() throws VaultException {
    for (int i = 1; i <= 10; i++) {
      Map<String, String> secret = new HashMap<String, String>();
      secret.put("key" + i, "value" + i);
      vault.logical().write("secret/path" + i, secret);
    }
  }

  /**
   * Utility method to delete the test secrets in the vault.
   * 
   * @throws VaultException
   */
  private static void deleteTestSecrets() throws VaultException {
    for (int i = 1; i <= 10; i++) {
      vault.logical().delete("secret/path" + i);
    }
  }
}
