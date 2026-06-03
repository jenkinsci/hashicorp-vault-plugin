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
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class VaultStepTest {

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
    public void engineVersionOverride_appliedToRead() {
        // Mixed KV v1/v2: a per-call engineVersion overrides the global default.
        TestStep step = new TestStep(PATH_AND_KEY, CREDENTIALS_ID);
        step.setEngineVersion("1");
        Map<String, String> data = new HashMap<>();
        data.put(SECRET_KEY, SECRET_VALUE);
        LogicalResponse response = mock(LogicalResponse.class);
        when(response.getData()).thenReturn(data);
        when(response.getRestResponse()).thenReturn(null);
        doReturn(response).when(mockAccessor).read(SECRET_PATH, 1);

        String result = step.fetchValue(SECRET_PATH, SECRET_KEY, run, listener);

        assertThat(result, equalTo(SECRET_VALUE));
        assertThat(step.capturedEngineVersion, equalTo(1));
    }

    @Test
    public void engineVersionDefault_usesGlobalWhenUnset() {
        TestStep step = stepWithValue(SECRET_VALUE);

        step.fetchValue(SECRET_PATH, SECRET_KEY, run, listener);

        assertThat(step.getEngineVersion(), is(nullValue()));
        assertThat(step.capturedEngineVersion, equalTo(2));
    }

    @Test
    public void engineVersionNonNumeric_throws() {
        TestStep step = new TestStep(PATH_AND_KEY, CREDENTIALS_ID);
        step.setEngineVersion("two");

        assertThrows(VaultPluginException.class,
            () -> step.fetchValue(SECRET_PATH, SECRET_KEY, run, listener));
    }

    @Test
    public void credentialsIdOptional_blankStillResolves() {
        // The old `vault` step falls back to the global credential when none is given.
        TestStep step = new TestStep(PATH_AND_KEY, null);
        Map<String, String> data = new HashMap<>();
        data.put(SECRET_KEY, SECRET_VALUE);
        LogicalResponse response = mock(LogicalResponse.class);
        when(response.getData()).thenReturn(data);
        when(response.getRestResponse()).thenReturn(null);
        doReturn(response).when(mockAccessor).read(SECRET_PATH, 2);

        String result = step.fetchValue(SECRET_PATH, SECRET_KEY, run, listener);

        assertThat(step.getCredentialsId(), is(nullValue()));
        assertThat(result, equalTo(SECRET_VALUE));
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

        VaultStep.Execution exec = new VaultStep.Execution(step, context);
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

        new VaultStep.Execution(step, context).run();

        assertThat(action.getValues(), is(empty()));
    }

    @Test
    public void splitting_lastSegmentBecomesKey() throws Exception {
        StepContext context = mock(StepContext.class);
        when(context.get(Run.class)).thenReturn(run);
        when(context.get(TaskListener.class)).thenReturn(listener);

        TestStep step = stepWithValue(SECRET_VALUE);

        new VaultStep.Execution(step, context).run();

        assertThat(step.capturedPath, equalTo(SECRET_PATH));
        assertThat(step.capturedKey, equalTo(SECRET_KEY));
    }

    @Test
    public void explicitKey_pathUsedVerbatim() throws Exception {
        StepContext context = mock(StepContext.class);
        when(context.get(Run.class)).thenReturn(run);
        when(context.get(TaskListener.class)).thenReturn(listener);

        // path is NOT split when an explicit key is supplied.
        TestStep step = new TestStep(SECRET_PATH, CREDENTIALS_ID);
        step.setKey(SECRET_KEY);
        stubRead(SECRET_PATH, SECRET_KEY, SECRET_VALUE);

        new VaultStep.Execution(step, context).run();

        assertThat(step.capturedPath, equalTo(SECRET_PATH));
        assertThat(step.capturedKey, equalTo(SECRET_KEY));
    }

    @Test
    public void explicitKey_singleSegmentPathDoesNotThrow() throws Exception {
        StepContext context = mock(StepContext.class);
        when(context.get(Run.class)).thenReturn(run);
        when(context.get(TaskListener.class)).thenReturn(listener);

        // Old-style single-segment path (e.g. `vault path: 'secrets', key: 'username'`).
        TestStep step = new TestStep("secrets", CREDENTIALS_ID);
        step.setKey("username");
        stubRead("secrets", "username", SECRET_VALUE);

        String result = new VaultStep.Execution(step, context).run();

        assertThat(step.capturedPath, equalTo("secrets"));
        assertThat(step.capturedKey, equalTo("username"));
        assertThat(result, equalTo(SECRET_VALUE));
    }

    @Test
    public void splitting_noSlash_throws() throws Exception {
        StepContext context = mock(StepContext.class);
        when(context.get(Run.class)).thenReturn(run);
        when(context.get(TaskListener.class)).thenReturn(listener);

        TestStep step = new TestStep("noslash", CREDENTIALS_ID);

        assertThrows(VaultPluginException.class,
            () -> new VaultStep.Execution(step, context).run());
    }

    @Test
    public void splitting_trailingSlash_throws() throws Exception {
        StepContext context = mock(StepContext.class);
        when(context.get(Run.class)).thenReturn(run);
        when(context.get(TaskListener.class)).thenReturn(listener);

        TestStep step = new TestStep("path/to/secret/", CREDENTIALS_ID);

        assertThrows(VaultPluginException.class,
            () -> new VaultStep.Execution(step, context).run());
    }

    // --- helpers ---

    private TestStep stepWithValue(String value) {
        TestStep step = new TestStep(PATH_AND_KEY, CREDENTIALS_ID);
        LogicalResponse response = mock(LogicalResponse.class);
        if (value != null) {
            Map<String, String> data = new HashMap<>();
            data.put(SECRET_KEY, value);
            when(response.getData()).thenReturn(data);
        } else {
            when(response.getData()).thenReturn(Collections.emptyMap());
        }
        when(response.getRestResponse()).thenReturn(null);
        doReturn(response).when(mockAccessor).read(SECRET_PATH, 2);
        return step;
    }

    private void stubRead(String path, String key, String value) {
        Map<String, String> data = new HashMap<>();
        data.put(key, value);
        LogicalResponse response = mock(LogicalResponse.class);
        when(response.getData()).thenReturn(data);
        when(response.getRestResponse()).thenReturn(null);
        doReturn(response).when(mockAccessor).read(path, 2);
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

    class TestStep extends VaultStep {

        final VaultConfiguration config = new VaultConfiguration();
        String capturedPath;
        String capturedKey;
        String capturedVaultUrl;
        String capturedVaultNamespace;
        Integer capturedEngineVersion;

        TestStep(String path, String credentialsId) {
            super(path);
            setCredentialsId(credentialsId);
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

            // Mirror the real per-call engineVersion override against the local config.
            if (getEngineVersion() != null) {
                try {
                    config.setEngineVersion(Integer.valueOf(getEngineVersion()));
                } catch (NumberFormatException e) {
                    throw new VaultPluginException(
                        "engineVersion must be an integer, got: " + getEngineVersion());
                }
            }
            capturedEngineVersion = config.getEngineVersion();

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
