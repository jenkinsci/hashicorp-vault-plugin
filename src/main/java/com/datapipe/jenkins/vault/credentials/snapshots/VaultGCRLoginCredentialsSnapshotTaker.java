package com.datapipe.jenkins.vault.credentials.snapshots;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import com.datapipe.jenkins.vault.credentials.SecretSnapshot;
import com.datapipe.jenkins.vault.credentials.common.VaultGCRLoginImpl;
import hudson.Extension;

@Extension
public class VaultGCRLoginCredentialsSnapshotTaker extends CredentialsSnapshotTaker<VaultGCRLoginImpl> {

    @Override
    public Class<VaultGCRLoginImpl> type() {
        return VaultGCRLoginImpl.class;
    }

    @Override
    public VaultGCRLoginImpl snapshot(
        VaultGCRLoginImpl credential) {
        SecretSnapshot snapshot = new SecretSnapshot(credential.getPassword());
        return new VaultGCRLoginImpl(credential.getScope(), credential.getId(), credential.getDescription(), snapshot);
    }
}
