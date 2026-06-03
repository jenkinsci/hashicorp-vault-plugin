package com.datapipe.jenkins.vault;

import com.datapipe.jenkins.vault.log.MaskingConsoleLogFilter;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Queue;
import hudson.model.Run;
import java.io.IOException;
import org.jenkinsci.plugins.workflow.flow.FlowExecutionOwner;
import org.jenkinsci.plugins.workflow.log.TaskListenerDecorator;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Pipeline-compatible console log decorator that masks secret values registered by
 * {@link VaultStep} in subsequent console output.
 *
 * <p>As a {@link TaskListenerDecorator.Factory}, this is invoked once per Pipeline build to
 * produce a decorator applied to every step's output stream. It ensures a
 * {@link VaultMaskedValuesAction} is present on the run so that values added later by
 * {@link VaultStep} are lazily picked up by {@link MaskingConsoleLogFilter}.
 */
@Restricted(NoExternalUse.class)
@Extension
public final class VaultMaskedValuesFilter implements TaskListenerDecorator.Factory {

    @Override
    public @CheckForNull TaskListenerDecorator of(@NonNull FlowExecutionOwner owner) {
        Queue.Executable executable;
        try {
            executable = owner.getExecutable();
        } catch (IOException e) {
            return null;
        }
        if (!(executable instanceof Run)) {
            return null;
        }
        Run<?, ?> run = (Run<?, ?>) executable;
        VaultMaskedValuesAction action = run.getAction(VaultMaskedValuesAction.class);
        if (action == null) {
            action = new VaultMaskedValuesAction();
            run.addOrReplaceAction(action);
        }
        return TaskListenerDecorator.fromConsoleLogFilter(
            new MaskingConsoleLogFilter(run.getCharset().name(), action.getValues())
        );
    }
}
