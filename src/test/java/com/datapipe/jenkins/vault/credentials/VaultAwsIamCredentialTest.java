package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VaultAwsIamCredentialTest {

    @Test
    void shouldSetCustomRoleIfValid() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setRole("custom-role");

        assertEquals("custom-role", vaultAwsIamCredential.getRole());
    }

    @Test
    void shouldSetCustomServerIdIfValid() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setServerId("some-server-id");

        assertEquals("some-server-id", vaultAwsIamCredential.getServerId());
    }

    @Test
    void shouldSetCustomMountPathIfValid() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setMountPath("custom-path");

        assertEquals("custom-path", vaultAwsIamCredential.getMountPath());
    }

    @Test
    void shouldSetDefaultMountPathIfEmptyMountPathIsSpecified() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setMountPath("");

        assertEquals("aws", vaultAwsIamCredential.getMountPath());
    }

    @Test
    void shouldSetDefaultMountPathIfNullMountPathIsSpecified() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setMountPath(null);

        assertEquals("aws", vaultAwsIamCredential.getMountPath());
    }

    @Test
    void shouldSetDefaultMountPathIfWhiteSpaceMountPathIsSpecified() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setMountPath("   ");

        assertEquals("aws", vaultAwsIamCredential.getMountPath());
    }
}
