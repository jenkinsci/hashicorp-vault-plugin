package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsScope;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class AbstractVaultTokenCredentialWithExpiration
    extends AbstractVaultTokenCredential {

    private final static Logger LOGGER = Logger
        .getLogger(AbstractVaultTokenCredentialWithExpiration.class.getName());

    private Calendar tokenExpiry;
    private String currentClientToken;

    protected AbstractVaultTokenCredentialWithExpiration(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
    }

    protected abstract String getToken(Vault vault);

    @Override
    public Vault authorizeWithVault(VaultConfig config) {
        Vault vault = getVault(config);
        if (tokenExpired()) {
            currentClientToken = getToken(vault);
            config.token(currentClientToken);
            setTokenExpiry(vault);
        } else {
            config.token(currentClientToken);
        }
        return vault;
    }

    protected Vault getVault(VaultConfig config) {
        return new Vault(config);
    }

    private void setTokenExpiry(Vault vault) {
        int tokenTTL = 0;
        try {
            tokenTTL = (int) vault.auth().lookupSelf().getTTL();
        } catch (VaultException e) {
            LOGGER.log(Level.WARNING, "Could not determine token expiration. " +
                "Check if token is allowed to access auth/token/lookup-self. " +
                "Assuming token TTL expired.", e);
        }
        tokenExpiry = Calendar.getInstance();
        tokenExpiry.add(Calendar.SECOND, tokenTTL);
    }

    private boolean tokenExpired() {
        if (tokenExpiry == null) {
            return true;
        }

        boolean result = true;
        Calendar now = Calendar.getInstance();
        long timeDiffInMillis = now.getTimeInMillis() - tokenExpiry.getTimeInMillis();
        if (timeDiffInMillis < -2000L) {
            // token will be valid for at least another 2s
            result = false;
            LOGGER.log(Level.FINE, "Auth token is still valid");
        } else {
            LOGGER.log(Level.FINE, "Auth token has to be re-issued" + timeDiffInMillis);
        }

        return result;
    }
}
