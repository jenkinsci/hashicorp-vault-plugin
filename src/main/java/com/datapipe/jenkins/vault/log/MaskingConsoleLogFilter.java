package com.datapipe.jenkins.vault.log;

import hudson.console.ConsoleLogFilter;
import hudson.console.LineTransformationOutputStream;
import hudson.model.Run;
import org.apache.commons.lang.StringUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*The logic in this class is borrowed from https://github.com/jenkinsci/credentials-binding-plugin/*/
public class MaskingConsoleLogFilter extends ConsoleLogFilter
        implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String charsetName;
    private List<String> valuesToMask;


    public MaskingConsoleLogFilter(final String charsetName,
                                   List<String> valuesToMask) {
        this.charsetName = charsetName;
        this.valuesToMask = valuesToMask;
    }

    @Override
    public OutputStream decorateLogger(Run run,
                                       final OutputStream logger) throws IOException, InterruptedException {
        return new LineTransformationOutputStream() {
            Pattern p;

            @Override
            protected void eol(byte[] b, int len) throws IOException {
                p = Pattern.compile(getPatternStringForSecrets(valuesToMask));
                if (StringUtils.isBlank(p.pattern())){
                    logger.write(b, 0, len);
                    return;
                }
                Matcher m = p.matcher(new String(b, 0, len, charsetName));
                if (m.find()) {
                    logger.write(m.replaceAll("****").getBytes(charsetName));
                } else {
                    // Avoid byte → char → byte conversion unless we are actually doing something.
                    logger.write(b, 0, len);
                }
            }
        };
    }

    /**
     * Utility method for turning a collection of secret strings into a single {@link String} for pattern compilation.
     *
     * @param secrets A collection of secret strings
     * @return A {@link String} generated from that collection.
     */
    public static String getPatternStringForSecrets(Collection<String> secrets) {
        StringBuilder b = new StringBuilder();
        List<String> sortedByLength = new ArrayList<String>(secrets.size());
        for (String secret : secrets) {
        	if (secret != null) sortedByLength.add(secret);
        }
        Collections.sort(sortedByLength, new Comparator<String>() {
            @Override
            public int compare(String o1, String o2) {
                return o2.length() - o1.length();
            }
        });

        for (String secret : sortedByLength) {
            if (b.length() > 0) {
                b.append('|');
            }
            b.append(Pattern.quote(secret));
        }
        return b.toString();
    }

}
