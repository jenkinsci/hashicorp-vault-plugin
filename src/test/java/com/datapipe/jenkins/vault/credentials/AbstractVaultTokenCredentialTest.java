package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Auth;
import com.bettercloud.vault.response.AuthResponse;
import com.bettercloud.vault.response.LookupResponse;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import org.junit.Before;
import org.junit.Test;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AbstractVaultTokenCredentialTest {

    private VaultConfig vaultConfig;
    private Auth auth;
    private AuthResponse authResponse;
    private LookupResponse lookupResponse;
    private ExampleVaultTokenCredential vaultTokenCredential;

    @Before
    public void setUp() throws VaultException {
        Vault vault = mock(Vault.class);
        vaultConfig = mock(VaultConfig.class);
        auth = mock(Auth.class);
        authResponse = mock(AuthResponse.class);
        lookupResponse = mock(LookupResponse.class);
        vaultTokenCredential = new ExampleVaultTokenCredential(vault);

        when(vault.auth()).thenReturn(auth);
        when(auth.loginByCert()).thenReturn(authResponse);
        when(authResponse.getAuthClientToken()).thenReturn("fakeToken");
    }

    @Test
    public void shouldBeAbleToFetchTokenOnInit() throws VaultException {
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(5L);

        vaultTokenCredential.authorizeWithVault(vaultConfig);

        verify(vaultConfig).token("fakeToken");
    }

    @Test
    public void shouldReuseTheExistingTokenIfNotExpired() throws VaultException {
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(5L);

        vaultTokenCredential.authorizeWithVault(vaultConfig);
        vaultTokenCredential.authorizeWithVault(vaultConfig);

        verify(vaultConfig, times(2)).token("fakeToken");
    }

    @Test
    public void shouldFetchNewTokenIfExpired() throws VaultException {
        when(authResponse.getAuthClientToken()).thenReturn("fakeToken1", "fakeToken2");
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(0L);

        vaultTokenCredential.authorizeWithVault(vaultConfig);
        vaultTokenCredential.authorizeWithVault(vaultConfig);

        verify(vaultConfig, times(2)).token(anyString());
        verify(vaultConfig).token("fakeToken1");
        verify(vaultConfig).token("fakeToken2");
    }

    @Test
    public void shouldExpireTokenImmediatelyIfExceptionFetchingTTL() throws VaultException {
        when(authResponse.getAuthClientToken()).thenReturn("fakeToken1", "fakeToken2");
        when(auth.lookupSelf()).thenThrow(new VaultException("Fail for testing"));

        vaultTokenCredential.authorizeWithVault(vaultConfig);
        vaultTokenCredential.authorizeWithVault(vaultConfig);

        verify(vaultConfig, times(2)).token(anyString());
        verify(vaultConfig).token("fakeToken1");
        verify(vaultConfig).token("fakeToken2");
    }

    static class ExampleVaultTokenCredential extends AbstractVaultTokenCredential {

        private final Vault vault;

        protected ExampleVaultTokenCredential(Vault vault) {
            super(CredentialsScope.GLOBAL, "id", "description");
            this.vault = vault;
        }

        @Override
        protected Vault getVault(VaultConfig config) {
            return vault;
        }

        @Override
        protected String getToken(Vault vault) {
            try {
                return vault.auth().loginByCert().getAuthClientToken();
            } catch (VaultException e) {
                throw new VaultPluginException(e.getMessage(), e);
            }
        }
    }
}
