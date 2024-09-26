package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import io.github.jopenlibs.vault.Vault;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.FileUtils;
import org.kohsuke.stapler.DataBoundConstructor;

public class VaultTokenFileCredential extends AbstractVaultTokenCredential {

    private String filepath;

    @DataBoundConstructor
    public VaultTokenFileCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id,
        @CheckForNull String description, @NonNull String filepath) {
        super(scope, id, description);
        this.filepath = filepath;
    }


    @Override
    public String getToken(Vault vault) {
        try {
            return FileUtils.readFileToString(new File(filepath), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new VaultPluginException("Failed to read token from file", e);
        }
    }

    public String getFilepath() {
        return filepath;
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Vault Token File Credential";
        }

    }
}
