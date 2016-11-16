package com.datapipe.jenkins.vault;

import hudson.console.ConsoleLogFilter;
import hudson.console.LineTransformationOutputStream;
import hudson.model.AbstractBuild;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.List;

public class MaskingConsoleLogFilter extends ConsoleLogFilter implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String charsetName;
    private List<String> valuesToMask;


    public MaskingConsoleLogFilter(final String charsetName, List<String> valuesToMask) {
        this.charsetName = charsetName;
        this.valuesToMask = valuesToMask;
    }

    @Override
    public OutputStream decorateLogger(AbstractBuild abstractBuild, final OutputStream logger) throws IOException, InterruptedException {
        return new LineTransformationOutputStream() {
            @Override
            protected void eol(byte[] b, int len) throws IOException {
                String logEntry = new String(b, 0, len, charsetName);
                for (String value : valuesToMask) {
                    logEntry = logEntry.replace(value, "****");
                }
                logger.write(logEntry.getBytes(charsetName));
            }
        };
    }
}
