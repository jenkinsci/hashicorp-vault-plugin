package com.datapipe.jenkins.vault.credentials.snapshots;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import com.datapipe.jenkins.vault.credentials.SecretSnapshot;
import com.datapipe.jenkins.vault.credentials.common.VaultCertificateCredentialsImpl;

public class VaultCerificateCredentialsSnapshotTaker extends CredentialsSnapshotTaker<VaultCertificateCredentialsImpl> {

    @Override
    public Class<VaultCertificateCredentialsImpl> type() {
        return VaultCertificateCredentialsImpl.class;
    }

    @Override
    public VaultCertificateCredentialsImpl snapshot(
        VaultCertificateCredentialsImpl credential) {
        SecretSnapshot password = new SecretSnapshot(credential.getPassword());
        SecretSnapshot keystoreBase64 = new SecretSnapshot(credential.getKeyStoreBase64());
        return new VaultCertificateCredentialsImpl(credential.getScope(), credential.getId(), credential.getDescription(), keystoreBase64, password);
    }
}
