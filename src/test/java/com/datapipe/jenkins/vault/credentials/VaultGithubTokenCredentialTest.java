package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Auth;
import io.github.jopenlibs.vault.response.AuthResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class VaultGithubTokenCredentialTest {

    @Test
    void shouldSetCustomMountPathIfSpecifiedValueIsValid() {

        VaultGithubTokenCredential vaultGithubTokenCredential = new VaultGithubTokenCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            null);
        vaultGithubTokenCredential.setMountPath("custom-path");

        assertEquals("custom-path", vaultGithubTokenCredential.getMountPath());
    }

    @Test
    void shouldSetDefaultMountPathIfEmptyMountPathIsSpecified() {

        VaultGithubTokenCredential vaultGithubTokenCredential = new VaultGithubTokenCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            null);
        vaultGithubTokenCredential.setMountPath("");

        assertEquals("github", vaultGithubTokenCredential.getMountPath());
    }

    @Test
    void shouldSetDefaultMountPathIfNullMountPathIsSpecified() {

        VaultGithubTokenCredential vaultGithubTokenCredential = new VaultGithubTokenCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            null);
        vaultGithubTokenCredential.setMountPath(null);

        assertEquals("github", vaultGithubTokenCredential.getMountPath());
    }

    @Test
    void shouldSetDefaultMountPathIfWhiteSpaceMountPathIsSpecified() {

        VaultGithubTokenCredential vaultGithubTokenCredential = new VaultGithubTokenCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            null);
        vaultGithubTokenCredential.setMountPath("   ");

        assertEquals("github", vaultGithubTokenCredential.getMountPath());
    }

    @Test
    void shouldUseCustomMountPathIfSpecified() throws VaultException {

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
