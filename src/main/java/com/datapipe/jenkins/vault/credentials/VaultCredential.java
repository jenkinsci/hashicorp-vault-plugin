package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.Serializable;
import java.util.List;

@NameWith(VaultCredential.NameProvider.class)
public interface VaultCredential extends StandardCredentials, Serializable {

    VaultAuthorizationResult authorizeWithVault(VaultConfig config, List<String> policies);

    class NameProvider extends CredentialsNameProvider<VaultCredential> {

        @NonNull
        public String getName(@NonNull VaultCredential credentials) {
            return credentials.getDescription();
        }
    }

    final class VaultAuthorizationResult {
        private final Vault vault;
        private final String token;

        public VaultAuthorizationResult(Vault vault, String token) {
            this.vault = vault;
            this.token = token;
        }

        public Vault getVault() {
            return vault;
        }

        public String getToken() {
            return token;
        }
    }
}
