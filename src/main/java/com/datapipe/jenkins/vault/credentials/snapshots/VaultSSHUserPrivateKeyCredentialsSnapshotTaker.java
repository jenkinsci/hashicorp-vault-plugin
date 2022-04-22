package com.datapipe.jenkins.vault.credentials.snapshots;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import com.datapipe.jenkins.vault.credentials.SecretSnapshot;
import com.datapipe.jenkins.vault.credentials.common.VaultSSHUserPrivateKeyImpl;
import hudson.util.Secret;

public class VaultSSHUserPrivateKeyCredentialsSnapshotTaker extends CredentialsSnapshotTaker<VaultSSHUserPrivateKeyImpl> {

    @Override
    public Class<VaultSSHUserPrivateKeyImpl> type() {
        return VaultSSHUserPrivateKeyImpl.class;
    }

    @Override
    public VaultSSHUserPrivateKeyImpl snapshot(
        VaultSSHUserPrivateKeyImpl credential) {
        SecretSnapshot passphrase = new SecretSnapshot(credential.getPassphrase());
        SecretSnapshot privateKey = new SecretSnapshot(Secret.fromString(credential.getPrivateKey()));
        SecretSnapshot username = new SecretSnapshot(Secret.fromString(credential.getUsername()));
        return new VaultSSHUserPrivateKeyImpl(credential.getScope(), credential.getId(), credential.getDescription(), username, privateKey, passphrase);
    }
}
