package com.datapipe.jenkins.vault.credentials;

import java.io.File;
import java.io.IOException;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

import com.bettercloud.vault.Vault;
import org.apache.commons.io.FileUtils;
import org.jenkinsci.remoting.RoleChecker;
import org.kohsuke.stapler.DataBoundConstructor;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;

import hudson.Extension;
import hudson.FilePath;
import hudson.remoting.VirtualChannel;

public class VaultTokenFileCredential extends AbstractVaultTokenCredential {
    private String filepath;

    @DataBoundConstructor
    public VaultTokenFileCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id, @CheckForNull String description, @Nonnull String filepath) {
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

                @Override public String invoke(File f, VirtualChannel channel) {
                    try {
                        return FileUtils.readFileToString(f);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }}).trim();
        } catch (IOException| InterruptedException e) {
            throw new VaultPluginException("Failed to read token from file", e);
        }
    }

    public String getFilepath(){
        return filepath;
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override public String getDisplayName() {
            return "Vault Token File Credential";
        }

    }
}
