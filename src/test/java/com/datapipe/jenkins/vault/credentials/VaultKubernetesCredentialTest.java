package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class VaultKubernetesCredentialTest {

    @Test
    public void shouldSetCustomMountPathIfValid() {
        VaultKubernetesCredential vaultKubernetesCredential = new VaultKubernetesCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            "role");

        vaultKubernetesCredential.setMountPath("custom-path");

        assertEquals("custom-path", vaultKubernetesCredential.getMountPath());
    }

    @Test
    public void shouldSetDefaultMountPathIfEmptyMountPathIsSpecified() {
        VaultKubernetesCredential vaultKubernetesCredential = new VaultKubernetesCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            "role");

        vaultKubernetesCredential.setMountPath("");

        assertEquals("kubernetes", vaultKubernetesCredential.getMountPath());
    }

    @Test
    public void shouldSetDefaultMountPathIfNullMountPathIsSpecified() {
        VaultKubernetesCredential vaultKubernetesCredential = new VaultKubernetesCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            "role");

        vaultKubernetesCredential.setMountPath(null);

        assertEquals("kubernetes", vaultKubernetesCredential.getMountPath());
    }

    @Test
    public void shouldSetDefaultMountPathIfWhiteSpaceMountPathIsSpecified() {
        VaultKubernetesCredential vaultKubernetesCredential = new VaultKubernetesCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description",
            "role");

        vaultKubernetesCredential.setMountPath("   ");

        assertEquals("kubernetes", vaultKubernetesCredential.getMountPath());
    }
}
