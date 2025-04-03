package com.datapipe.jenkins.vault.log;

import hudson.console.ConsoleLogFilter;
import hudson.model.Run;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.jenkinsci.plugins.credentialsbinding.masking.SecretPatterns;

/*The logic in this class is borrowed from https://github.com/jenkinsci/credentials-binding-plugin/*/
public class MaskingConsoleLogFilter extends ConsoleLogFilter
    implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String charsetName;
    private final List<String> valuesToMask;
    private Pattern pattern;
    private List<String> valuesToMaskInUse;

    public MaskingConsoleLogFilter(final String charsetName,
        List<String> valuesToMask) {
        this.charsetName = charsetName;
        this.valuesToMask = valuesToMask;
        updatePattern();
    }

    private synchronized Pattern updatePattern() {
        if (!valuesToMask.equals(valuesToMaskInUse)) {
            List<String> values = valuesToMask.stream().filter(Objects::nonNull).collect(Collectors.toList());
            pattern = values.isEmpty() ? null : SecretPatterns.getAggregateSecretPattern(values);
            valuesToMaskInUse = new ArrayList<>(valuesToMask);
        }
        return pattern;
    }

    @Override
    public OutputStream decorateLogger(Run run,
        final OutputStream logger) throws IOException, InterruptedException {
        return new SecretPatterns.MaskingOutputStream(logger,
                // Only return a non-null pattern once there are secrets to mask. When a non-null
                // pattern is returned it is cached and not supplied again. In cases like
                // VaultBuildWrapper the secrets are added to the "valuesToMasker" list AFTER
                // construction AND AFTER the decorateLogger method is initially called, therefore
                // the Pattern should only be returned once the secrets have been made available.
                // Not to mention it is also a slight optimization when there is are no secrets
                // to mask.
                this::updatePattern,
            charsetName);
    }

}
