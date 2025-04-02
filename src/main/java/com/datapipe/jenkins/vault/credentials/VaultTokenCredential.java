package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;
import io.github.jopenlibs.vault.Vault;
import org.kohsuke.stapler.DataBoundConstructor;

public class VaultTokenCredential extends AbstractVaultTokenCredential {

    private Secret token;

    @DataBoundConstructor
    public VaultTokenCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id,
        @CheckForNull String description, @NonNull Secret token) {
        super(scope, id, description);
        this.token = token;
    }

    @NonNull
    public Secret getToken() {
        return token;
    }

    @Override
    public String getToken(Vault vault) {
        return Secret.toString(token);
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Vault Token Credential";
        }

    }
}
