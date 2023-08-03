package com.datapipe.jenkins.vault.log;

import hudson.console.ConsoleLogFilter;
import hudson.model.Run;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.regex.Pattern;
import org.jenkinsci.plugins.credentialsbinding.masking.SecretPatterns;

/*The logic in this class is borrowed from https://github.com/jenkinsci/credentials-binding-plugin/*/
public class MaskingConsoleLogFilter extends ConsoleLogFilter
    implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String charsetName;
    private final Pattern pattern;



    public MaskingConsoleLogFilter(final String charsetName,
        List<String> valuesToMask) {
        this.charsetName = charsetName;

        // Filter out null values
        List<String> values = valuesToMask.stream().filter(Objects::nonNull).collect(Collectors.toList());

        if (!valuesToMask.isEmpty()) {
            this.pattern = SecretPatterns.getAggregateSecretPattern(values);
        } else {
            this.pattern = null;
        }
    }

    @Override
    public OutputStream decorateLogger(Run run,
        final OutputStream logger) throws IOException, InterruptedException {
        return new SecretPatterns.MaskingOutputStream(logger,
            () -> pattern,
            charsetName);
    }

    }
