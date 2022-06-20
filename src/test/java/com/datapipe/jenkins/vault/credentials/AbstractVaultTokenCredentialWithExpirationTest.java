package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Auth;
import com.bettercloud.vault.api.Auth.TokenRequest;
import com.bettercloud.vault.response.AuthResponse;
import com.bettercloud.vault.response.LookupResponse;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Before;
import org.junit.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AbstractVaultTokenCredentialWithExpirationTest {

    private Vault vault;
    private VaultConfig vaultConfig;
    private Auth auth;
    private AuthResponse authResponse, childAuthResponse;
    private LookupResponse lookupResponse;
    private ExampleVaultTokenCredentialWithExpiration vaultTokenCredentialWithExpiration;
    private List<String> policies;

    @Before
    public void setUp() throws VaultException {
        policies = Arrays.asList("pol1", "pol2");
        vault = mock(Vault.class);
        vaultConfig = mock(VaultConfig.class);
        auth = mock(Auth.class);
        authResponse = mock(AuthResponse.class);
        childAuthResponse = mock(AuthResponse.class);
        when(auth.createToken(any(TokenRequest.class))).thenReturn(childAuthResponse);
        lookupResponse = mock(LookupResponse.class);
        vaultTokenCredentialWithExpiration = new ExampleVaultTokenCredentialWithExpiration(vault);

        when(vault.auth()).thenReturn(auth);
        when(auth.loginByCert()).thenReturn(authResponse);
        when(authResponse.getAuthClientToken()).thenReturn("fakeToken");
        when(childAuthResponse.getAuthClientToken()).thenReturn("childToken");
    }

    @Test
    public void shouldBeAbleToFetchTokenOnInit() throws VaultException {
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(5L);

        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, null);

        verify(vaultConfig).token("fakeToken");
    }

    @Test
    public void shouldFetchNewTokenForDifferentPolicies() throws VaultException {
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(5L);
        when(authResponse.getAuthClientToken()).thenReturn("fakeToken1", "fakeToken2");
        when(childAuthResponse.getAuthClientToken()).thenReturn("childToken1", "childToken2");

        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, null);
        verify(vaultConfig).token("fakeToken1");
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, policies);
        verify(vaultConfig).token("childToken1");
    }

    @Test
    public void shouldNotFetchChildTokenIfEmptyPoliciesSpecified() throws VaultException {
        when(authResponse.getAuthClientToken()).thenReturn("fakeToken");
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(0L);
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, new ArrayList<>());

        verify(vaultConfig, times(1)).token(anyString());
        verify(vaultConfig).token("fakeToken");
    }

    @Test
    public void shouldFetchChildTokenIfPoliciesSpecified() throws VaultException {
        TokenRequest tokenRequest = (new TokenRequest()).polices(policies);
        when(auth.createToken(argThat((TokenRequest tr) -> tokenRequest.getPolices() == policies)))
            .thenReturn(childAuthResponse);
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(0L);

        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, policies);

        verify(vaultConfig, times(2)).token(anyString());
        verify(vaultConfig).token("fakeToken");
        verify(vaultConfig).token("childToken");
    }

    @Test
    public void shouldReuseTheExistingTokenIfNotExpired() throws VaultException {
        when(authResponse.getAuthClientToken()).thenReturn("fakeToken1", "fakeToken2");
        when(childAuthResponse.getAuthClientToken()).thenReturn("childToken1", "childToken2");
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(5L);

        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, null);
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, null);
        verify(vaultConfig, times(2)).token("fakeToken1");

        // Different policies results in a new token
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, policies);
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, policies);
        verify(vaultConfig, times(2)).token("childToken1");
    }

    @Test
    public void shouldFetchNewTokenIfExpired() throws VaultException {
        when(authResponse.getAuthClientToken()).thenReturn("fakeToken1", "fakeToken2");
        when(childAuthResponse.getAuthClientToken()).thenReturn("childToken1", "childToken2");
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(0L);

        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, null);
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, null);
        verify(vaultConfig, times(2)).token(anyString());
        verify(vaultConfig).token("fakeToken1");
        verify(vaultConfig).token("fakeToken2");

        // Different policies results in a new token
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, policies);
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, policies);
        verify(vaultConfig).token("childToken1");
        verify(vaultConfig).token("childToken2");
    }

    @Test
    public void shouldExpireTokenImmediatelyIfExceptionFetchingTTL() throws VaultException {
        when(authResponse.getAuthClientToken()).thenReturn("fakeToken1", "fakeToken2");
        when(auth.lookupSelf()).thenThrow(new VaultException("Fail for testing"));

        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, null);
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, null);

        verify(vaultConfig, times(2)).token(anyString());
        verify(vaultConfig).token("fakeToken1");
        verify(vaultConfig).token("fakeToken2");
    }

    static class ExampleVaultTokenCredentialWithExpiration extends
        AbstractVaultTokenCredentialWithExpiration {

        private final Vault vault;

        protected ExampleVaultTokenCredentialWithExpiration(Vault vault) {
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
