package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import java.io.Serializable;
import java.util.List;

@NameWith(VaultCredential.NameProvider.class)
public interface VaultCredential extends StandardCredentials, Serializable {

    Vault authorizeWithVault(VaultConfig config, List<String> policies, String role);

    class NameProvider extends CredentialsNameProvider<VaultCredential> {

        @NonNull
        public String getName(@NonNull VaultCredential credentials) {
            return credentials.getDescription();
        }
    }
}
