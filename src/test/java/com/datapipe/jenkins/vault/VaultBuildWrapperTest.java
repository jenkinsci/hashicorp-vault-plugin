package com.datapipe.jenkins.vault;

import static org.junit.Assert.assertThat;
import static org.hamcrest.CoreMatchers.containsString;

import java.io.IOException;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;

import org.jvnet.hudson.test.JenkinsRule;

import hudson.model.*;
import hudson.tasks.Shell;

import org.apache.commons.io.FileUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;


public class VaultBuildWrapperTest {

  private static VaultDevServer vaultServer;

  @Rule
  public JenkinsRule j = new JenkinsRule();

  @BeforeClass
  public static void setUp() throws IOException, VaultException, InterruptedException {
    VaultBuildWrapperTest.vaultServer = new VaultDevServer("testToken");
    VaultBuildWrapperTest.vaultServer.startServer();
    Vault vault =
        new Vault(new VaultConfig("http://127.0.0.1:8200", "testToken"));

    // Sleep here to allow the vault server to start up
    Thread.sleep(4000);

    Map<String, String> secrets = new HashMap<String, String>();
    secrets.put("value", "test");

    vault.logical().write("secret/testing", secrets);
  }

  @AfterClass
  public static void tearDown() {
    VaultBuildWrapperTest.vaultServer.stopServer();
  }

  @Test
  public void first() throws Exception {
    List<VaultSecret> secrets = new ArrayList<VaultSecret>();
    VaultSecret secret = new VaultSecret("secret/testing", "value", "envVar");
    secrets.add(secret);
    VaultBuildWrapper vaultBuildWrapper = new VaultBuildWrapper(secrets);
    vaultBuildWrapper.setAuthToken("testToken");
    vaultBuildWrapper.setVaultUrl("http://127.0.0.1:8200");
    FreeStyleProject project = j.createFreeStyleProject();
    project.getBuildWrappersList().add(vaultBuildWrapper);
    project.getBuildersList().add(new Shell("echo $envVar"));
    FreeStyleBuild build = project.scheduleBuild2(0).get();
    String log = FileUtils.readFileToString(build.getLogFile());
    assertThat(log, containsString("+ echo test"));
  }
}
