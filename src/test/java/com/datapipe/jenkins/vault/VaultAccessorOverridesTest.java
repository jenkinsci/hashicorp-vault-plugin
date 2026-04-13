package com.datapipe.jenkins.vault;

import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import com.datapipe.jenkins.vault.model.VaultSecret;
import hudson.EnvVars;
import hudson.model.Job;
import hudson.model.Run;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Collections;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class VaultAccessorOverridesTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private Run mockRun() {
        Run run = mock(Run.class);
        Job parent = mock(Job.class);
        when(run.getParent()).thenReturn(parent);
        return run;
    }

    private EnvVars mockEnv(String prefix) {
        EnvVars env = mock(EnvVars.class);
        when(env.expand(Mockito.anyString())).thenAnswer(inv -> inv.getArgument(0));
        when(env.get("JOB_NAME")).thenReturn("job1");
        when(env.get("JOB_BASE_NAME")).thenReturn("job1");
        when(env.get("NODE_NAME")).thenReturn("node1");
        return env;
    }

    private VaultConfiguration baseConfig(boolean verbose) {
        VaultConfiguration cfg = new VaultConfiguration();
        cfg.setVaultUrl("https://vault.example");
        cfg.setEngineVersion(2);
        cfg.setSkipSslVerification(true);
        cfg.setVerboseLogging(verbose);
        cfg.fixDefaults();
        return cfg;
    }

    @Test
    public void verboseLogging_off_doesNotPrintBaseConfig() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream logger = new PrintStream(baos);

        VaultConfiguration cfg = baseConfig(false);
        Run<?,?> run = mockRun();
        EnvVars env = mockEnv("");

        VaultAccessor.retrieveVaultSecrets(run, logger, env, new VaultAccessor(), cfg, Collections.emptyList());

        String logs = baos.toString();
        // Should not include the base config line when verbose=false
        assertThat(logs, org.hamcrest.Matchers.not(containsString("Vault: url=")));
    }

    @Test
    public void verboseLogging_on_printsBaseConfig() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream logger = new PrintStream(baos);

        VaultConfiguration cfg = baseConfig(true);
        Run<?,?> run = mockRun();
        EnvVars env = mockEnv("");

        VaultAccessor.retrieveVaultSecrets(run, logger, env, new VaultAccessor(), cfg, Collections.emptyList());

        String logs = baos.toString();
        assertThat(logs, containsString("Vault: url=https://vault.example"));
    }

    @Test
    public void noCredentialConfiguredForSecret_throwsHelpfulError() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream logger = new PrintStream(baos);

        VaultConfiguration cfg = baseConfig(false);
        cfg.setPrefixPath("kv/");

        Run<?,?> run = mockRun();
        EnvVars env = mockEnv("");

        VaultSecret secret = new VaultSecret("team/secret", Collections.emptyList());

        thrown.expect(VaultPluginException.class);
        thrown.expectMessage("No credential configured for secret 'kv/team/secret'");

        VaultAccessor.retrieveVaultSecrets(run, logger, env, new VaultAccessor(), cfg, Collections.singletonList(secret));
    }
}
