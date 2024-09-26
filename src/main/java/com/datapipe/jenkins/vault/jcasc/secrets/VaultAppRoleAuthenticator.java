package com.datapipe.jenkins.vault.jcasc.secrets;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public class VaultAppRoleAuthenticator extends VaultAuthenticatorWithExpiration {

    private final static Logger LOGGER = Logger.getLogger(VaultAppRoleAuthenticator.class.getName());

    private VaultAppRole appRole;

    public VaultAppRoleAuthenticator(VaultAppRole appRole, String mountPath) {
        this.appRole = appRole;
        this.mountPath = mountPath;
    }

    public void authenticate(Vault vault, VaultConfig config) throws VaultException {
        if (isTokenTTLExpired()) {
            // authenticate
            currentAuthToken = vault.auth()
                .loginByAppRole(mountPath, appRole.getAppRole(), appRole.getAppRoleSecret())
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
        return Objects.hash(appRole);
    }
}
