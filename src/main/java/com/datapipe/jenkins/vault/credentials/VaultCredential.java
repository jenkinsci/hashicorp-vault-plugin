package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.Serializable;

@NameWith(VaultCredential.NameProvider.class)
public interface VaultCredential extends StandardCredentials, Serializable {

    Vault authorizeWithVault(VaultConfig config);

    class NameProvider extends CredentialsNameProvider<VaultCredential> {

        @NonNull
        public String getName(@NonNull VaultCredential credentials) {
            return credentials.getDescription();
        }
    }
}
