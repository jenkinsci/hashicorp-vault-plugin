package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;

@NameWith(value = VaultUsernamePasswordCredential.NameProvider.class, priority = 1)
public interface VaultUsernamePasswordCredential extends StandardUsernameCredentials, UsernamePasswordCredentials {

    String getDisplayName();

    class NameProvider extends CredentialsNameProvider<VaultUsernamePasswordCredential> {

        @NonNull
        @Override
        public String getName(VaultUsernamePasswordCredential hashicorpVaultCredentials) {
            String description = Util.fixEmpty(hashicorpVaultCredentials.getDescription());
            return hashicorpVaultCredentials.getDisplayName() + (description == null ? "" : " (" + description + ")");
        }
    }
}
