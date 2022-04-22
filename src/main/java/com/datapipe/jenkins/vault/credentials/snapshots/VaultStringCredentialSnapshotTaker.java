package com.datapipe.jenkins.vault.credentials.snapshots;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import com.datapipe.jenkins.vault.credentials.SecretSnapshot;
import com.datapipe.jenkins.vault.credentials.common.VaultStringCredential;
import com.datapipe.jenkins.vault.credentials.common.VaultStringCredentialImpl;

public class VaultStringCredentialSnapshotTaker extends CredentialsSnapshotTaker<VaultStringCredential> {

    @Override
    public Class<VaultStringCredential> type() {
        return VaultStringCredential.class;
    }

    @Override
    public VaultStringCredential snapshot(
        VaultStringCredential credential) {
        SecretSnapshot snapshot = new SecretSnapshot(credential.getSecret());
        return new VaultStringCredentialImpl(credential.getScope(), credential.getId(), credential.getDescription(), snapshot);
    }
}
