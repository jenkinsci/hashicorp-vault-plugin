package com.datapipe.jenkins.vault;

import com.datapipe.jenkins.vault.log.MaskingConsoleLogFilter;
import hudson.Extension;
import hudson.console.ConsoleLogFilter;
import hudson.model.Run;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serial;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Global console log filter that registers a {@link VaultMaskedValuesAction} on every build and
 * wraps the console output with a {@link MaskingConsoleLogFilter} backed by that action's mutable
 * value list.
 *
 * <p>Because {@link MaskingConsoleLogFilter} evaluates the pattern lazily, values added later by
 * {@link VaultCredentialsStep} are automatically masked in subsequent console output.
 */
@Restricted(NoExternalUse.class)
@Extension
public final class VaultMaskedValuesFilter extends ConsoleLogFilter {

    @Serial
    private static final long serialVersionUID = 1L;

    @Override
    public OutputStream decorateLogger(Run run, OutputStream logger)
            throws IOException, InterruptedException {
        VaultMaskedValuesAction action = new VaultMaskedValuesAction();
        run.addOrReplaceAction(action);
        return new MaskingConsoleLogFilter(run.getCharset().name(), action.getValues())
            .decorateLogger(run, logger);
    }
}
