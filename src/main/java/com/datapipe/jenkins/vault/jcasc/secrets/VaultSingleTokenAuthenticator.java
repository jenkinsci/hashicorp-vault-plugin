package com.datapipe.jenkins.vault.jcasc.secrets;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;

public class VaultSingleTokenAuthenticator implements VaultAuthenticator {
    private String token;

    public VaultSingleTokenAuthenticator(String token) {
        this.token = token;
    }

    public void authenticate(Vault vault, VaultConfig config) throws VaultException {
        // No special mechanism - token already exists
        config.token(token).build();
    }
}
