package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Auth;
import com.bettercloud.vault.api.Auth.TokenRequest;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.kohsuke.stapler.DataBoundSetter;

public abstract class AbstractVaultTokenCredentialWithExpiration
    extends AbstractVaultTokenCredential {

    protected final static Logger LOGGER = Logger
        .getLogger(AbstractVaultTokenCredentialWithExpiration.class.getName());

    @CheckForNull
    private Boolean usePolicies;

    /**
     * Get if the configured policies should be used or not.
     * @return true if the policies should be used, false or null otherwise
     */
    @CheckForNull
    public Boolean getUsePolicies() {
        return usePolicies;
    }

    /**
     * Set if the configured policies are used or not.
     * @param usePolicies true if policies should be used, false otherwise
     */
    @DataBoundSetter
    public void setUsePolicies(Boolean usePolicies) {
        this.usePolicies = usePolicies;
    }

    private transient Map<String, Calendar> tokenExpiry;
    private transient Map<String, String> tokenCache;

    protected AbstractVaultTokenCredentialWithExpiration(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
        tokenExpiry = new HashMap<>();
        tokenCache = new HashMap<>();
    }

    protected abstract String getToken(Vault vault);

    /**
     * Retrieve the Vault auth client. May be overridden in subclasses.
     * @param vault the Vault instance
     * @return the Vault auth client
     */
    protected Auth getVaultAuth(@NonNull Vault vault) {
        return vault.auth();
    }

    /**
     * Retrieves a new child token with specific policies if this credential is configured to use
     * policies and a list of requested policies is provided.
     * @param vault the vault instance
     * @param policies the policies list
     * @return the new token or null if it cannot be provisioned
     */
    protected String getChildToken(Vault vault, List<String> policies) {
        if (usePolicies == null || !usePolicies || policies == null || policies.isEmpty()) {
            return null;
        }
        Auth auth = getVaultAuth(vault);
        try {
            String ttl = String.format("%ds", getTokenTTL(vault));
            TokenRequest tokenRequest = (new TokenRequest())
                .polices(policies)
                // Set the TTL to the parent token TTL
                .ttl(ttl);
            LOGGER.log(Level.FINE, "Requesting child token with policies {0} and TTL {1}",
                new Object[] {policies, ttl});
            return auth.createToken(tokenRequest).getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("Could not retrieve token with policies from Vault", e);
        }
    }

    /**
     * Retrieves a key to be used for the token cache based on a list of policies.
     * @param policies the list of policies
     * @return the key to use for the map, either an empty string or a comma-separated list of policies
     */
    private String getCacheKey(List<String> policies) {
        if (policies == null || policies.isEmpty()) {
            return "";
        }
        return String.join(",", policies);
    }

    @Override
    public Vault authorizeWithVault(VaultConfig config, List<String> policies) {
        // Upgraded instances can have these not initialized in the constructor (serialized jobs possibly)
        if (tokenCache == null) {
            tokenCache = new HashMap<>();
            tokenExpiry = new HashMap<>();
        }

        String cacheKey = getCacheKey(policies);
        Vault vault = getVault(config);
        if (tokenExpired(cacheKey)) {
            tokenCache.put(cacheKey, getToken(vault));
            config.token(tokenCache.get(cacheKey));

            // After current token is configured, try to retrieve a new child token with limited policies
            String childToken = getChildToken(vault, policies);
            if (childToken != null) {
                // A new token was generated, put it in the cache and configure vault
                tokenCache.put(cacheKey, childToken);
                config.token(childToken);
            }
            setTokenExpiry(vault, cacheKey);
        } else {
            config.token(tokenCache.get(cacheKey));
        }
        return vault;
    }

    protected Vault getVault(VaultConfig config) {
        return new Vault(config);
    }

    private long getTokenTTL(Vault vault) throws VaultException {
        return getVaultAuth(vault).lookupSelf().getTTL();
    }

    private void setTokenExpiry(Vault vault, String cacheKey) {
        int tokenTTL = 0;
        try {
            tokenTTL = (int) getTokenTTL(vault);
        } catch (VaultException e) {
            LOGGER.log(Level.WARNING, "Could not determine token expiration for policies '" +
                cacheKey + "'. Check if token is allowed to access auth/token/lookup-self. " +
                "Assuming token TTL expired.", e);
        }
        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.SECOND, tokenTTL);
        tokenExpiry.put(cacheKey, expiry);
    }

    private boolean tokenExpired(String cacheKey) {
        Calendar expiry = tokenExpiry.get(cacheKey);
        if (expiry == null) {
            return true;
        }

        boolean result = true;
        Calendar now = Calendar.getInstance();
        long timeDiffInMillis = now.getTimeInMillis() - expiry.getTimeInMillis();
        LOGGER.log(Level.FINE, "Expiration for " + cacheKey + " is " + expiry + ", diff: " + timeDiffInMillis);
        if (timeDiffInMillis < -10000L) {
            // token will be valid for at least another 10s
            result = false;
            LOGGER.log(Level.FINE, "Auth token is still valid for policies '" + cacheKey + "'");
        } else {
            LOGGER.log(Level.FINE,"Auth token has to be re-issued for policies '" + cacheKey +
                    "' (" + timeDiffInMillis + "ms difference)");
        }

        return result;
    }
}
