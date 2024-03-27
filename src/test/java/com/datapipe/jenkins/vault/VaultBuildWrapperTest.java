package com.datapipe.jenkins.vault;

import com.bettercloud.vault.response.LogicalResponse;
import com.bettercloud.vault.rest.RestResponse;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import com.datapipe.jenkins.vault.model.VaultSecret;
import com.datapipe.jenkins.vault.model.VaultSecretValue;
import hudson.EnvVars;
import hudson.model.Build;
import hudson.model.Run;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import jenkins.tasks.SimpleBuildWrapper;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class VaultBuildWrapperTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testWithNonExistingPath() throws IOException, InterruptedException {
        String path = "not/existing";
        VaultAccessor mockAccessor = mock(VaultAccessor.class);
        doReturn(mockAccessor).when(mockAccessor).init();
        LogicalResponse response = getNotFoundResponse();
        when(mockAccessor.read(path, 2)).thenReturn(response);
        TestWrapper wrapper = new TestWrapper(standardSecrets(path), mockAccessor);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream logger = new PrintStream(baos);
        SimpleBuildWrapper.Context context = null;
        Run<?, ?> build = mock(Build.class);
        EnvVars envVars = mock(EnvVars.class);
        when(envVars.expand(path)).thenReturn(path);

        wrapper.run(context, build, envVars, logger);

        try { // now we expect the exception to raise
            wrapper.vaultConfig.setFailIfNotFound(true);
            wrapper.run(context, build, envVars, logger);
        } catch (VaultPluginException e) {
            assertThat(e.getMessage(), is("Vault credentials not found for 'not/existing'"));
        }

        verify(mockAccessor, times(2)).init();
        verify(mockAccessor, times(2)).read(path, 2);
        assertThat(new String(baos.toByteArray(), StandardCharsets.UTF_8),
            containsString("Vault credentials not found for 'not/existing'"));
    }

    @Test
    public void testWithAccessDeniedPath() throws IOException, InterruptedException {
        String path = "not/allowed";
        VaultAccessor mockAccessor = mock(VaultAccessor.class);
        doReturn(mockAccessor).when(mockAccessor).init();
        LogicalResponse response = getAccessDeniedResponse();
        when(mockAccessor.read(path, 2)).thenReturn(response);
        TestWrapper wrapper = new TestWrapper(standardSecrets(path), mockAccessor);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream logger = new PrintStream(baos);
        SimpleBuildWrapper.Context context = null;
        Run<?, ?> build = mock(Build.class);
        when(build.getParent()).thenReturn(null);
        EnvVars envVars = mock(EnvVars.class);
        when(envVars.expand(path)).thenReturn(path);

        try {
            wrapper.run(context, build, envVars, logger);
        } catch (VaultPluginException e) {
            assertThat(e.getMessage(), is("Access denied to Vault path 'not/allowed'"));
        }

        verify(mockAccessor).init();
        verify(mockAccessor).read(path, 2);
    }

    private List<VaultSecret> standardSecrets(String path) {
        List<VaultSecret> secrets = new ArrayList<>();
        VaultSecretValue secretValue = new VaultSecretValue("envVar1", "key1");
        List<VaultSecretValue> secretValues = new ArrayList<>();
        secretValues.add(secretValue);
        VaultSecret secret = new VaultSecret(path, secretValues);
        secret.setEngineVersion(2);
        secrets.add(secret);
        return secrets;
    }

    private LogicalResponse getNotFoundResponse() {
        LogicalResponse resp = mock(LogicalResponse.class);
        RestResponse rest = mock(RestResponse.class);
        when(resp.getRestResponse()).thenReturn(rest);
        when(rest.getStatus()).thenReturn(404);
        return resp;
    }

    private LogicalResponse getAccessDeniedResponse() {
        LogicalResponse resp = mock(LogicalResponse.class);
        RestResponse rest = mock(RestResponse.class);
        when(resp.getData()).thenReturn(new HashMap<>());
        when(resp.getRestResponse()).thenReturn(rest);
        when(rest.getStatus()).thenReturn(403);
        return resp;
    }

    class TestWrapper extends VaultBuildWrapper {

        VaultConfiguration vaultConfig = new VaultConfiguration();

        public TestWrapper(List<VaultSecret> vaultSecrets, VaultAccessor mockAccessor) {
            super(vaultSecrets);

            vaultConfig.setVaultUrl("testmock");
            vaultConfig.setVaultCredentialId("credId");
            vaultConfig.setFailIfNotFound(false);
            setVaultAccessor(mockAccessor);
            setConfiguration(vaultConfig);
        }

        public void run(Context context, Run build, EnvVars envVars, PrintStream logger) {
            this.logger = logger;
            provideEnvironmentVariablesFromVault(context, build, envVars);
        }
    }
}
