package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.FilePath;
import hudson.remoting.VirtualChannel;
import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FileUtils;
import org.jenkinsci.remoting.RoleChecker;
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
        FilePath file = new FilePath(new File(filepath));
        try {
            return file.act(new FilePath.FileCallable<String>() {
                @Override
                public void checkRoles(RoleChecker roleChecker) throws SecurityException {
                    //not needed
                }

                @Override
                public String invoke(File f, VirtualChannel channel) {
                    try {
                        return FileUtils.readFileToString(f);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }).trim();
        } catch (IOException | InterruptedException e) {
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
