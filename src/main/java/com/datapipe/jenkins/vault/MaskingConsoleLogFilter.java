package com.datapipe.jenkins.vault;

import hudson.console.ConsoleLogFilter;
import hudson.console.LineTransformationOutputStream;
import hudson.model.AbstractBuild;
import hudson.model.Run;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.List;

/**
 * Created by tobiaslarscheid on 14.11.16.
 */
public class MaskingConsoleLogFilter extends ConsoleLogFilter implements Serializable{
    final Run<?, ?> build;
    private List<String> valuesToMask;


    public MaskingConsoleLogFilter(final Run<?, ?> build, List<String> valuesToMask){
        this.build= build;
        this.valuesToMask = valuesToMask;
    }

    @Override
    public OutputStream decorateLogger(AbstractBuild abstractBuild, final OutputStream logger) throws IOException, InterruptedException {
        return new LineTransformationOutputStream() {
            @Override protected void eol(byte[] b, int len) throws IOException {
                String logEntry = new String(b, 0, len, build.getCharset().name());
                for (String value : valuesToMask) {
                    logEntry = logEntry.replace(value, "****");
                }
                logger.write(logEntry.getBytes(build.getCharset().name()));
            }
        };
    }
}
