package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class VaultAwsIamCredentialTest {

    @Test
    public void shouldSetCustomRoleIfValid() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setRole("custom-role");

        assertEquals("custom-role", vaultAwsIamCredential.getRole());
    }

    @Test
    public void shouldSetCustomServerIdIfValid() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setServerId("some-server-id");

        assertEquals("some-server-id", vaultAwsIamCredential.getServerId());
    }

    @Test
    public void shouldSetCustomMountPathIfValid() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setMountPath("custom-path");

        assertEquals("custom-path", vaultAwsIamCredential.getMountPath());
    }

    @Test
    public void shouldSetDefaultMountPathIfEmptyMountPathIsSpecified() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setMountPath("");

        assertEquals("aws", vaultAwsIamCredential.getMountPath());
    }

    @Test
    public void shouldSetDefaultMountPathIfNullMountPathIsSpecified() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setMountPath(null);

        assertEquals("aws", vaultAwsIamCredential.getMountPath());
    }

    @Test
    public void shouldSetDefaultMountPathIfWhiteSpaceMountPathIsSpecified() {
        VaultAwsIamCredential vaultAwsIamCredential = new VaultAwsIamCredential(
            CredentialsScope.GLOBAL,
            "id",
            "description");

        vaultAwsIamCredential.setMountPath("   ");

        assertEquals("aws", vaultAwsIamCredential.getMountPath());
    }
}
