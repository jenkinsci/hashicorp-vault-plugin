package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VaultKubernetesCredentialTest {

    @Test
    void shouldSetCustomMountPathIfValid() {
        VaultKubernetesCredential vaultKubernetesCredential = new VaultKubernetesCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            "role");

        vaultKubernetesCredential.setMountPath("custom-path");

        assertEquals("custom-path", vaultKubernetesCredential.getMountPath());
    }

    @Test
    void shouldSetDefaultMountPathIfEmptyMountPathIsSpecified() {
        VaultKubernetesCredential vaultKubernetesCredential = new VaultKubernetesCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            "role");

        vaultKubernetesCredential.setMountPath("");

        assertEquals("kubernetes", vaultKubernetesCredential.getMountPath());
    }

    @Test
    void shouldSetDefaultMountPathIfNullMountPathIsSpecified() {
        VaultKubernetesCredential vaultKubernetesCredential = new VaultKubernetesCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            "role");

        vaultKubernetesCredential.setMountPath(null);

        assertEquals("kubernetes", vaultKubernetesCredential.getMountPath());
    }

    @Test
    void shouldSetDefaultMountPathIfWhiteSpaceMountPathIsSpecified() {
        VaultKubernetesCredential vaultKubernetesCredential = new VaultKubernetesCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            "role");

        vaultKubernetesCredential.setMountPath("   ");

        assertEquals("kubernetes", vaultKubernetesCredential.getMountPath());
    }
}
