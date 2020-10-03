package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Auth;
import com.bettercloud.vault.response.AuthResponse;
import com.cloudbees.plugins.credentials.CredentialsScope;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class VaultGithubTokenCredentialTest {

    @Test
    public void shouldSetCustomMountPathIfSpecifiedValueIsValid() {

        VaultGithubTokenCredential vaultGithubTokenCredential = new VaultGithubTokenCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            null);
        vaultGithubTokenCredential.setMountPath("custom-path");

        assertEquals("custom-path", vaultGithubTokenCredential.getMountPath());
    }

    @Test
    public void shouldSetDefaultMountPathIfEmptyMountPathIsSpecified() {

        VaultGithubTokenCredential vaultGithubTokenCredential = new VaultGithubTokenCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            null);
        vaultGithubTokenCredential.setMountPath("");

        assertEquals("github", vaultGithubTokenCredential.getMountPath());
    }

    @Test
    public void shouldSetDefaultMountPathIfNullMountPathIsSpecified() {

        VaultGithubTokenCredential vaultGithubTokenCredential = new VaultGithubTokenCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            null);
        vaultGithubTokenCredential.setMountPath(null);

        assertEquals("github", vaultGithubTokenCredential.getMountPath());
    }

    @Test
    public void shouldSetDefaultMountPathIfWhiteSpaceMountPathIsSpecified() {

        VaultGithubTokenCredential vaultGithubTokenCredential = new VaultGithubTokenCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            null);
        vaultGithubTokenCredential.setMountPath("   ");

        assertEquals("github", vaultGithubTokenCredential.getMountPath());
    }

    @Test
    public void shouldUseCustomMountPathIfSpecified() throws VaultException {

        VaultGithubTokenCredential vaultGithubTokenCredential = new VaultGithubTokenCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            null);

        Vault mockVault = mock(Vault.class);
        Auth mockAuth = mock(Auth.class);
        AuthResponse mockAuthResponse = mock(AuthResponse.class);
        String expectedToken = "token";
        when(mockVault.auth()).thenReturn(mockAuth);
        when(mockAuth.loginByGithub("", "github")).thenReturn(mockAuthResponse);
        when(mockAuthResponse.getAuthClientToken()).thenReturn(expectedToken);

        String actualToken = vaultGithubTokenCredential.getToken(mockVault);

        assertEquals(expectedToken, actualToken);
    }

}
