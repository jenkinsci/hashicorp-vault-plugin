package com.datapipe.jenkins.vault.credentials.common;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.ItemGroup;

/**
 * Vault-backed credentials that resolve the Vault configuration from the folder (or Jenkins
 * root) they are stored in.
 *
 * <p>{@link com.datapipe.jenkins.vault.credentials.VaultCredentialsProvider} sets the context
 * on every credential implementing this interface, so a folder-scoped credential talks to the
 * folder's Vault configuration instead of silently falling back to the global one.</p>
 */
public interface VaultContextualCredentials {

    void setContext(@NonNull ItemGroup context);

    ItemGroup getContext();
}
