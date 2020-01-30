package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;

@NameWith(value = VaultSSHUserPrivateKey.NameProvider.class, priority = 32)
public interface VaultSSHUserPrivateKey extends SSHUserPrivateKey {

    String getDisplayName();

    class NameProvider extends CredentialsNameProvider<VaultSSHUserPrivateKey> {

        @NonNull
        @Override
        public String getName(VaultSSHUserPrivateKey hashicorpVaultCredentials) {
            String description = Util.fixEmpty(hashicorpVaultCredentials.getDescription());
            return hashicorpVaultCredentials.getDisplayName() + (description == null ? ""
                : " (" + description + ")");
        }
    }
}
