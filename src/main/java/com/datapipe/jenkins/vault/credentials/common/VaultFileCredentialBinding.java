package com.datapipe.jenkins.vault.credentials.common;

import hudson.Extension;
import hudson.FilePath;
import java.io.IOException;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.impl.AbstractOnDiskBinding;
import org.kohsuke.stapler.DataBoundConstructor;

public class VaultFileCredentialBinding extends AbstractOnDiskBinding<VaultFileCredential> {

    @DataBoundConstructor
    public VaultFileCredentialBinding(String variable, String credentialsId) {
        super(variable, credentialsId);
    }

    @Override protected Class<VaultFileCredential> type() {
        return VaultFileCredential.class;
    }

    @Override protected final FilePath write(VaultFileCredential credentials, FilePath dir) throws IOException, InterruptedException {
        FilePath secret = dir.child(credentials.getFileName());
        secret.copyFrom(credentials.getContent());
        secret.chmod(0700); // note: it's a directory
        return secret;
    }

    @Symbol("vaultFile")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<VaultFileCredential> {

        @Override public boolean requiresWorkspace() {
            return true;
        }

        @Override protected Class<VaultFileCredential> type() {
            return VaultFileCredential.class;
        }

        @Override public String getDisplayName() {
            return "Vault Secret File Credential";
        }

    }
}
