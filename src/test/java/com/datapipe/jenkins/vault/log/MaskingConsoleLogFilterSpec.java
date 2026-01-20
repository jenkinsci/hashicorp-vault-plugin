package com.datapipe.jenkins.vault.log;

import hudson.ExtensionList;
import hudson.model.Run;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import jenkins.model.Jenkins;
import jenkins.util.JenkinsJVM;
import org.jenkinsci.plugins.credentialsbinding.masking.LiteralSecretPatternFactory;
import org.jenkinsci.plugins.credentialsbinding.masking.SecretPatternFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class MaskingConsoleLogFilterSpec {

    private @Mock(answer = Answers.CALLS_REAL_METHODS) MockedStatic<SecretPatternFactory> secretPatternFactoryMockedStatic;

    private @Mock MockedStatic<JenkinsJVM> jenkinsJvmMockedStatic;

    @BeforeEach
    void setup() {
        ExtensionList<SecretPatternFactory> factories = ExtensionList.create((Jenkins) null, SecretPatternFactory.class);
        factories.add(new LiteralSecretPatternFactory());
        secretPatternFactoryMockedStatic.when(SecretPatternFactory::all).thenReturn(factories);
    }

    @Test
    void shouldCorrectlyMask() throws IOException, InterruptedException {
        MaskingConsoleLogFilter filter = new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(),
            Collections.singletonList("secret"));
        ByteArrayOutputStream resultingLog = new ByteArrayOutputStream();

        OutputStream maskingLogger = filter.decorateLogger(mock(Run.class), resultingLog);

        maskingLogger.write("This is a test.\n".getBytes(StandardCharsets.UTF_8));
        maskingLogger.write("This is secret test.\n".getBytes(StandardCharsets.UTF_8));

        String[] resultingLines = resultingLog.toString(StandardCharsets.UTF_8).split("\\n");

        assertThat(resultingLines[0], is("This is a test."));
        assertThat(resultingLines[1], is("This is **** test."));
    }

    @Test
    void shouldCorrectlyMaskOverlappingSecrets() throws IOException, InterruptedException {
        MaskingConsoleLogFilter filter = new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(),
            Arrays.asList("secret", "veryverysecret"));
        ByteArrayOutputStream resultingLog = new ByteArrayOutputStream();

        OutputStream maskingLogger = filter.decorateLogger(mock(Run.class), resultingLog);

        maskingLogger.write("This is a test.\n".getBytes(StandardCharsets.UTF_8));
        maskingLogger.write("This is veryverysecret test.\n".getBytes(StandardCharsets.UTF_8));
        maskingLogger.write("This is secret test.\n".getBytes(StandardCharsets.UTF_8));

        String[] resultingLines = resultingLog.toString(StandardCharsets.UTF_8).split("\\n");

        assertThat(resultingLines[0], is("This is a test."));
        assertThat(resultingLines[1], is("This is **** test."));
        assertThat(resultingLines[1], is("This is **** test."));
    }

    @Test
    void shouldCorrectlyHandleEmptyList() throws Exception {
        MaskingConsoleLogFilter filter = new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(),
            Collections.emptyList());
        ByteArrayOutputStream resultingLog = new ByteArrayOutputStream();

        OutputStream maskingLogger = filter.decorateLogger(mock(Run.class), resultingLog);

        maskingLogger.write("This is a test.\n".getBytes(StandardCharsets.UTF_8));
        maskingLogger.write("This is veryverysecret test.\n".getBytes(StandardCharsets.UTF_8));

        String[] resultingLines = resultingLog.toString(StandardCharsets.UTF_8).split("\\n");

        assertThat(resultingLines[0], is("This is a test."));
        assertThat(resultingLines[1], is("This is veryverysecret test."));
    }

    @Test
    void shouldFilterNullSecrets() throws Exception {
        List<String> secrets = Arrays.asList("secret", null, "another", null, "test");
        MaskingConsoleLogFilter filter = new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(),
            secrets);

        ByteArrayOutputStream resultingLog = new ByteArrayOutputStream();

        OutputStream maskingLogger = filter.decorateLogger(mock(Run.class), resultingLog);
        maskingLogger.write("This is a test.\n".getBytes(StandardCharsets.UTF_8));
        String[] resultingLines = resultingLog.toString(StandardCharsets.UTF_8).split("\\n");

        assertThat(resultingLines[0], is("This is a ****."));
    }

}
