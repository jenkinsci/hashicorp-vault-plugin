package com.datapipe.jenkins.vault;

import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import hudson.model.Run;
import hudson.model.TaskListener;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class VaultCredentialsStepTest {

    private static final String SECRET_PATH = "secret/myapp/db";
    private static final String SECRET_KEY = "password";
    private static final String PATH_AND_KEY = SECRET_PATH + "/" + SECRET_KEY;
    private static final String SECRET_VALUE = "super-secret";
    private static final String CREDENTIALS_ID = "vault-approle";

    private VaultAccessor mockAccessor;
    private Run<?, ?> run;
    private TaskListener listener;

    @Before
    public void setUp() {
        mockAccessor = mock(VaultAccessor.class);
        doReturn(mockAccessor).when(mockAccessor).init();

        run = mock(Run.class);
        when(run.getParent()).thenReturn(null);

        PrintStream logger = new PrintStream(new ByteArrayOutputStream());
        listener = mock(TaskListener.class);
        when(listener.getLogger()).thenReturn(logger);
    }

    @Test
    public void happyPath_returnsValue() {
        TestStep step = stepWithValue(SECRET_VALUE);

        String result = step.fetchValue(SECRET_PATH, SECRET_KEY, run, listener);

        assertThat(result, equalTo(SECRET_VALUE));
    }

    @Test
    public void keyNotFound_throwsWhenFailIfNotFound() {
        TestStep step = stepWithValue(null);
        step.config.setFailIfNotFound(true);

        VaultPluginException ex = assertThrows(VaultPluginException.class,
            () -> step.fetchValue(SECRET_PATH, SECRET_KEY, run, listener));
        assertThat(ex.getMessage(), containsString(SECRET_KEY));
        assertThat(ex.getMessage(), containsString(SECRET_PATH));
    }

    @Test
    public void keyNotFound_returnsEmptyWhenSoftFailure() {
        TestStep step = stepWithValue(null);
        step.config.setFailIfNotFound(false);

        String result = step.fetchValue(SECRET_PATH, SECRET_KEY, run, listener);

        assertThat(result, equalTo(""));
    }

    @Test
    public void pathNotFound_returnsEmptyWhenSoftFailure() {
        LogicalResponse notFound = notFoundResponse();
        TestStep step = new TestStep(PATH_AND_KEY, CREDENTIALS_ID);
        step.config.setFailIfNotFound(false);
        doReturn(notFound).when(mockAccessor).read(SECRET_PATH, 2);

        String result = step.fetchValue(SECRET_PATH, SECRET_KEY, run, listener);

        assertThat(result, equalTo(""));
    }

    @Test
    public void accessDenied_alwaysThrows() {
        LogicalResponse denied = accessDeniedResponse();
        TestStep step = new TestStep(PATH_AND_KEY, CREDENTIALS_ID);
        doReturn(denied).when(mockAccessor).read(SECRET_PATH, 2);

        assertThrows(VaultPluginException.class,
            () -> step.fetchValue(SECRET_PATH, SECRET_KEY, run, listener));
    }

    @Test
    public void vaultUrlOverride_capturedCorrectly() {
        TestStep step = stepWithValue(SECRET_VALUE);
        step.setVaultUrl("https://my-vault.example.com");

        step.fetchValue(SECRET_PATH, SECRET_KEY, run, listener);

        assertThat(step.capturedVaultUrl, equalTo("https://my-vault.example.com"));
    }

    @Test
    public void vaultNamespaceOverride_capturedCorrectly() {
        TestStep step = stepWithValue(SECRET_VALUE);
        step.setVaultNamespace("prod");

        step.fetchValue(SECRET_PATH, SECRET_KEY, run, listener);

        assertThat(step.capturedVaultNamespace, equalTo("prod"));
    }

    @Test
    public void maskingEnabled_addsValueToAction() throws Exception {
        VaultMaskedValuesAction action = new VaultMaskedValuesAction();
        when(run.getAction(VaultMaskedValuesAction.class)).thenReturn(action);

        StepContext context = mock(StepContext.class);
        when(context.get(Run.class)).thenReturn(run);
        when(context.get(TaskListener.class)).thenReturn(listener);

        TestStep step = stepWithValue(SECRET_VALUE);
        step.setMaskSecret(true);

        VaultCredentialsStep.Execution exec = new VaultCredentialsStep.Execution(step, context);
        String result = exec.run();

        assertThat(result, equalTo(SECRET_VALUE));
        assertThat(action.getValues(), equalTo(Collections.singletonList(SECRET_VALUE)));
    }

    @Test
    public void maskingDisabled_doesNotAddToAction() throws Exception {
        VaultMaskedValuesAction action = new VaultMaskedValuesAction();
        when(run.getAction(VaultMaskedValuesAction.class)).thenReturn(action);

        StepContext context = mock(StepContext.class);
        when(context.get(Run.class)).thenReturn(run);
        when(context.get(TaskListener.class)).thenReturn(listener);

        TestStep step = stepWithValue(SECRET_VALUE);
        step.setMaskSecret(false);

        new VaultCredentialsStep.Execution(step, context).run();

        assertThat(action.getValues(), is(empty()));
    }

    @Test
    public void splitting_lastSegmentBecomesKey() throws Exception {
        StepContext context = mock(StepContext.class);
        when(context.get(Run.class)).thenReturn(run);
        when(context.get(TaskListener.class)).thenReturn(listener);

        TestStep step = stepWithValue(SECRET_VALUE);

        new VaultCredentialsStep.Execution(step, context).run();

        assertThat(step.capturedPath, equalTo(SECRET_PATH));
        assertThat(step.capturedKey, equalTo(SECRET_KEY));
    }

    @Test
    public void splitting_noSlash_throws() throws Exception {
        StepContext context = mock(StepContext.class);
        when(context.get(Run.class)).thenReturn(run);
        when(context.get(TaskListener.class)).thenReturn(listener);

        TestStep step = new TestStep("noslash", CREDENTIALS_ID);

        assertThrows(VaultPluginException.class,
            () -> new VaultCredentialsStep.Execution(step, context).run());
    }

    @Test
    public void splitting_trailingSlash_throws() throws Exception {
        StepContext context = mock(StepContext.class);
        when(context.get(Run.class)).thenReturn(run);
        when(context.get(TaskListener.class)).thenReturn(listener);

        TestStep step = new TestStep("path/to/secret/", CREDENTIALS_ID);

        assertThrows(VaultPluginException.class,
            () -> new VaultCredentialsStep.Execution(step, context).run());
    }

    // --- helpers ---

    private TestStep stepWithValue(String value) {
        TestStep step = new TestStep(PATH_AND_KEY, CREDENTIALS_ID);
        if (value != null) {
            Map<String, String> data = new HashMap<>();
            data.put(SECRET_KEY, value);
            LogicalResponse response = mock(LogicalResponse.class);
            when(response.getData()).thenReturn(data);
            when(response.getRestResponse()).thenReturn(null);
            doReturn(response).when(mockAccessor).read(SECRET_PATH, 2);
        } else {
            LogicalResponse response = mock(LogicalResponse.class);
            when(response.getData()).thenReturn(Collections.emptyMap());
            when(response.getRestResponse()).thenReturn(null);
            doReturn(response).when(mockAccessor).read(SECRET_PATH, 2);
        }
        return step;
    }

    private LogicalResponse notFoundResponse() {
        LogicalResponse resp = mock(LogicalResponse.class);
        RestResponse rest = mock(RestResponse.class);
        when(resp.getData()).thenReturn(Collections.emptyMap());
        when(resp.getRestResponse()).thenReturn(rest);
        when(rest.getStatus()).thenReturn(404);
        return resp;
    }

    private LogicalResponse accessDeniedResponse() {
        LogicalResponse resp = mock(LogicalResponse.class);
        RestResponse rest = mock(RestResponse.class);
        when(resp.getData()).thenReturn(Collections.emptyMap());
        when(resp.getRestResponse()).thenReturn(rest);
        when(rest.getStatus()).thenReturn(403);
        return resp;
    }

    class TestStep extends VaultCredentialsStep {

        final VaultConfiguration config = new VaultConfiguration();
        String capturedPath;
        String capturedKey;
        String capturedVaultUrl;
        String capturedVaultNamespace;

        TestStep(String path, String credentialsId) {
            super(path, credentialsId);
            config.setVaultUrl("https://vault.test");
            config.setVaultCredentialId(credentialsId);
            config.setFailIfNotFound(true);
            config.setEngineVersion(2);
            config.fixDefaults();
        }

        @Override
        protected String fetchValue(String path, String key, Run<?, ?> run, TaskListener listener) {
            capturedPath = path;
            capturedKey = key;
            capturedVaultUrl = getVaultUrl();
            capturedVaultNamespace = getVaultNamespace();

            if (config.getVaultUrl() == null || config.getVaultUrl().isBlank()) {
                throw new VaultPluginException("vaultUrl is not configured");
            }

            mockAccessor.setConfig(config.getVaultConfig());
            mockAccessor.setMaxRetries(config.getMaxRetries());
            mockAccessor.setRetryIntervalMilliseconds(config.getRetryIntervalMilliseconds());
            mockAccessor.init();

            LogicalResponse response = mockAccessor.read(path, config.getEngineVersion());

            if (VaultAccessor.responseHasErrors(config, listener.getLogger(), path, response)) {
                return "";
            }

            Map<String, String> data = response.getData();
            String value = data != null ? data.get(key) : null;

            if (value == null || value.isBlank()) {
                if (config.getFailIfNotFound()) {
                    throw new VaultPluginException(
                        "Key '" + key + "' not found at Vault path '" + path + "'");
                }
                return "";
            }
            return value;
        }
    }
}
