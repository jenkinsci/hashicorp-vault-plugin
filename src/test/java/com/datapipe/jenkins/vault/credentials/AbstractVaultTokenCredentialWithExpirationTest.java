package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Auth;
import io.github.jopenlibs.vault.api.Auth.TokenRequest;
import io.github.jopenlibs.vault.response.AuthResponse;
import io.github.jopenlibs.vault.response.LookupResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AbstractVaultTokenCredentialWithExpirationTest {

    private Vault vault;
    private VaultConfig vaultConfig;
    private Auth auth;
    private AuthResponse authResponse, childAuthResponse;
    private LookupResponse lookupResponse;
    private ExampleVaultTokenCredentialWithExpiration vaultTokenCredentialWithExpiration;
    private List<String> policies;

    @BeforeEach
    void setUp() throws VaultException {
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
    void shouldBeAbleToFetchTokenOnInit() throws VaultException {
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(5L);

        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, null);

        verify(vaultConfig).token("fakeToken");
    }

    @Test
    void shouldFetchNewTokenForDifferentPolicies() throws VaultException {
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
    void shouldNotFetchChildTokenIfEmptyPoliciesSpecified() throws VaultException {
        when(authResponse.getAuthClientToken()).thenReturn("fakeToken");
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(0L);
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, new ArrayList<>());

        verify(vaultConfig, times(1)).token(anyString());
        verify(vaultConfig).token("fakeToken");
    }

    @Test
    void shouldFetchChildTokenIfPoliciesSpecified() throws VaultException {
        when(auth.createToken(argThat((TokenRequest tr) ->
            tr.getPolices() == policies && tr.getTtl().equals("30s")
        ))).thenReturn(childAuthResponse);
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        // First response is for parent, second is for child
        when(lookupResponse.getTTL()).thenReturn(30L, 0L);

        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, policies);

        verify(vaultConfig, times(2)).token(anyString());
        verify(vaultConfig).token("fakeToken");
        verify(vaultConfig).token("childToken");
    }

    @Test
    void shouldReuseTheExistingTokenIfNotExpired() throws VaultException {
        when(authResponse.getAuthClientToken()).thenReturn("fakeToken1", "fakeToken2");
        when(childAuthResponse.getAuthClientToken()).thenReturn("childToken1", "childToken2");
        when(auth.lookupSelf()).thenReturn(lookupResponse);
        when(lookupResponse.getTTL()).thenReturn(30L);

        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, null);
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, null);
        verify(vaultConfig, times(2)).token("fakeToken1");

        // Different policies results in a new token
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, policies);
        vaultTokenCredentialWithExpiration.authorizeWithVault(vaultConfig, policies);
        verify(vaultConfig, times(2)).token("childToken1");
    }

    @Test
    void shouldFetchNewTokenIfExpired() throws VaultException {
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
    void shouldExpireTokenImmediatelyIfExceptionFetchingTTL() throws VaultException {
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
            this.setUsePolicies(true);
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
