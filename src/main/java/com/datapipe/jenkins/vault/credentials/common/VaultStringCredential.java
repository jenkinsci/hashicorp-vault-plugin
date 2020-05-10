package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;

@NameWith(value = VaultStringCredential.NameProvider.class, priority = 32)
public interface VaultStringCredential extends StringCredentials {

    String getDisplayName();

    class NameProvider extends CredentialsNameProvider<VaultStringCredential> {

        @NonNull
        @Override
        public String getName(VaultStringCredential hashicorpVaultCredentials) {
            String description = Util.fixEmpty(hashicorpVaultCredentials.getDescription());
            return hashicorpVaultCredentials.getDisplayName() + (description == null ? ""
                : " (" + description + ")");
        }
    }
}
