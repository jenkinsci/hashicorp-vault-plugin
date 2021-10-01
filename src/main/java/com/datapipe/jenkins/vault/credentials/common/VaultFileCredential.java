package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import org.jenkinsci.plugins.plaincredentials.FileCredentials;

@NameWith(value = VaultFileCredential.NameProvider.class, priority = 32)
public interface VaultFileCredential extends FileCredentials {
    String getDisplayName();

    class NameProvider extends CredentialsNameProvider<VaultFileCredential> {

        @NonNull
        @Override
        public String getName(VaultFileCredential hashicorpVaultCredentials) {
            String description = Util.fixEmpty(hashicorpVaultCredentials.getDescription());
            return hashicorpVaultCredentials.getDisplayName() + (description == null ? ""
                : " (" + description + ")");
        }
    }

}
