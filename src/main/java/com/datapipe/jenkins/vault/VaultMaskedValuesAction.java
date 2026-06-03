package com.datapipe.jenkins.vault;

import hudson.model.Action;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Per-build action that accumulates secret values registered by {@link VaultStep}
 * for console log masking. Values are appended as each step call resolves them, and are picked up
 * lazily by {@link VaultMaskedValuesFilter} which holds a reference to the same list.
 */
@Restricted(NoExternalUse.class)
public final class VaultMaskedValuesAction implements Action {

    private final List<String> values = new CopyOnWriteArrayList<>();

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getUrlName() {
        return null;
    }

    public void add(String value) {
        values.add(value);
    }

    public List<String> getValues() {
        return values;
    }
}
