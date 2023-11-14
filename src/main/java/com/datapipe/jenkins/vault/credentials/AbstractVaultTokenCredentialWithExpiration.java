package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsScope;
import java.util.Calendar;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class AbstractVaultTokenCredentialWithExpiration
    extends AbstractVaultTokenCredential {

    private final static Logger LOGGER = Logger
        .getLogger(AbstractVaultTokenCredentialWithExpiration.class.getName());

    public static class CacheKey {
        private final String vaultUrl;
        private final String namespace;

        public CacheKey(String vaultUrl, String namespace) {
            this.vaultUrl = vaultUrl;
            this.namespace = namespace;
        }

        @Override
        public String toString() {
            return String.format("vaultUrl=%s, namespace=%s", vaultUrl, namespace);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof CacheKey)) {
                return false;
            }
            CacheKey cacheKey = (CacheKey) o;
            return Objects.equals(vaultUrl, cacheKey.vaultUrl) && Objects.equals(
                namespace, cacheKey.namespace);
        }

        @Override
        public int hashCode() {
            return Objects.hash(vaultUrl, namespace);
        }
    }

    public static class TokenHolder {
        private final CacheKey key;
        private Calendar tokenExpiry;
        private String token;

        public TokenHolder(CacheKey key) {
            this.key = key;
        }

        public synchronized Vault authorizeWithVault(
            AbstractVaultTokenCredentialWithExpiration credentials, VaultConfig config) {
            Vault vault = credentials.getVault(config);
            if (tokenExpired()) {
                token = credentials.getToken(vault);
                config.token(token);
                setTokenExpiry(vault);
            } else {
                config.token(token);
            }
            return vault;
        }

        private void setTokenExpiry(Vault vault) {
            int tokenTTL = 0;
            try {
                tokenTTL = (int) vault.auth().lookupSelf().getTTL();
            } catch (VaultException e) {
                LOGGER.log(Level.WARNING,
                    String.format("Could not determine token expiration (for key %s). ", key) +
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
                LOGGER.log(Level.FINE, String.format("Auth token (for key %s) is still valid", key));
            } else {
                LOGGER.log(Level.FINE,
                    String.format("Auth token (for key %s) has to be re-issued (%d)",
                        key, timeDiffInMillis));
            }

            return result;
        }
    }

    private ConcurrentMap<CacheKey, TokenHolder> cache = new ConcurrentHashMap<>();

    private synchronized ConcurrentMap<CacheKey, TokenHolder> getCache() {
        if (cache == null) {
            cache = new ConcurrentHashMap<>();
        }
        return cache;
    }

    protected AbstractVaultTokenCredentialWithExpiration(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
    }

    protected abstract String getToken(Vault vault);

    @Override
    public Vault authorizeWithVault(VaultConfig config) {
        ConcurrentMap<CacheKey, TokenHolder> cache = getCache();
        CacheKey key = new CacheKey(config.getAddress(), config.getNameSpace());
        cache.putIfAbsent(key, new TokenHolder(key));
        TokenHolder holder = cache.get(key);
        return holder.authorizeWithVault(this, config);
    }

    protected Vault getVault(VaultConfig config) {
        return new Vault(config);
    }
}
