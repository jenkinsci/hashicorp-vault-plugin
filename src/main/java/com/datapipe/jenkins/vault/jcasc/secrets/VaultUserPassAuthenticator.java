package com.datapipe.jenkins.vault.jcasc.secrets;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public class VaultUserPassAuthenticator extends VaultAuthenticatorWithExpiration {

    private final static Logger LOGGER = Logger
        .getLogger(VaultUserPassAuthenticator.class.getName());

    private VaultUsernamePassword userPass;

    public VaultUserPassAuthenticator(
        VaultUsernamePassword userPass,
        String mountPath) {
        this.userPass = userPass;
        this.mountPath = mountPath;
    }

    public void authenticate(Vault vault, VaultConfig config) throws VaultException {
        if (isTokenTTLExpired()) {
            // authenticate
            currentAuthToken = vault.auth()
                .loginByUserPass(userPass.getUsername(), userPass.getPassword(), mountPath)
                .getAuthClientToken();
            config.token(currentAuthToken).build();
            LOGGER.log(Level.FINE, "Login to Vault using AppRole/SecretID successful");
            getTTLExpiryOfCurrentToken(vault);
        } else {
            // make sure current auth token is set in config
            config.token(currentAuthToken).build();
        }
    }

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userPass, mountPath);
    }
}
