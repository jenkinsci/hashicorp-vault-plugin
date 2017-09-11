package com.datapipe.jenkins.vault.log;

import hudson.model.Run;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

@RunWith(MockitoJUnitRunner.class)
public class MaskingConsoleLogFilterSpec {
    @Test
    public void shouldCorrectlyMask() throws IOException, InterruptedException {
        MaskingConsoleLogFilter filter = new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(), Arrays.asList("secret"));
        ByteArrayOutputStream resultingLog = new ByteArrayOutputStream();

        OutputStream maskingLogger = filter.decorateLogger(mock(Run.class), resultingLog);

        maskingLogger.write("This is a test.\n".getBytes(StandardCharsets.UTF_8));
        maskingLogger.write("This is secret test.\n".getBytes(StandardCharsets.UTF_8));

        String[] resultingLines = resultingLog.toString(StandardCharsets.UTF_8.name()).split("\\n");

        assertThat(resultingLines[0], is("This is a test."));
        assertThat(resultingLines[1], is("This is **** test."));
    }

    @Test
    public void shouldCorrectlyMaskOverlappingSecrets() throws IOException, InterruptedException {
        MaskingConsoleLogFilter filter = new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(), Arrays.asList("secret", "veryverysecret"));
        ByteArrayOutputStream resultingLog = new ByteArrayOutputStream();

        OutputStream maskingLogger = filter.decorateLogger(mock(Run.class), resultingLog);

        maskingLogger.write("This is a test.\n".getBytes(StandardCharsets.UTF_8));
        maskingLogger.write("This is veryverysecret test.\n".getBytes(StandardCharsets.UTF_8));
        maskingLogger.write("This is secret test.\n".getBytes(StandardCharsets.UTF_8));

        String[] resultingLines = resultingLog.toString(StandardCharsets.UTF_8.name()).split("\\n");

        assertThat(resultingLines[0], is("This is a test."));
        assertThat(resultingLines[1], is("This is **** test."));
        assertThat(resultingLines[1], is("This is **** test."));
    }

    @Test
    public void shouldCorrectlyHandleEmptyList() throws Exception {
        MaskingConsoleLogFilter filter = new MaskingConsoleLogFilter(StandardCharsets.UTF_8.name(), Collections.<String>emptyList());
        ByteArrayOutputStream resultingLog = new ByteArrayOutputStream();

        OutputStream maskingLogger = filter.decorateLogger(mock(Run.class), resultingLog);

        maskingLogger.write("This is a test.\n".getBytes(StandardCharsets.UTF_8));
        maskingLogger.write("This is veryverysecret test.\n".getBytes(StandardCharsets.UTF_8));

        String[] resultingLines = resultingLog.toString(StandardCharsets.UTF_8.name()).split("\\n");

        assertThat(resultingLines[0], is("This is a test."));
        assertThat(resultingLines[1], is("This is veryverysecret test."));
    }

    @Test
    public void shouldFilterNullSecrets() throws Exception {
        List<String> secrets = Arrays.asList("secret", null, "another", null, "last");

        try {
            String pattern = MaskingConsoleLogFilter.getPatternStringForSecrets(secrets);
            assertThat(pattern, is("\\Qanother\\E|\\Qsecret\\E|\\Qlast\\E"));
        } catch (NullPointerException npe) {
            fail("NullPointerException thrown");
        }
    }
}