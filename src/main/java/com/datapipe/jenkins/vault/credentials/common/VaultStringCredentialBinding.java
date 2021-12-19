package com.datapipe.jenkins.vault.credentials.common;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.Secret;
import java.io.IOException;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.Binding;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

public class VaultStringCredentialBinding extends Binding<VaultStringCredential> {


    @DataBoundConstructor
    public VaultStringCredentialBinding(String variable, String credentialsId) {
        super(variable, credentialsId);
    }

    @Override protected Class<VaultStringCredential> type() {
        return VaultStringCredential.class;
    }

    @Override public SingleEnvironment bindSingle(@Nonnull Run<?,?> build,
                                                  @Nullable FilePath workspace,
                                                  @Nullable Launcher launcher,
                                                  @Nonnull TaskListener listener) throws IOException, InterruptedException {
        return new SingleEnvironment(Secret.toString(getCredentials(build).getSecret()));
    }

    @Symbol("vaultString")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<VaultStringCredential> {

        @Override public boolean requiresWorkspace() {
            return false;
        }

        @Override protected Class<VaultStringCredential> type() {
            return VaultStringCredential.class;
        }

        @Override public String getDisplayName() {
            return "Vault Secret Text Credential";
        }

    }
}
