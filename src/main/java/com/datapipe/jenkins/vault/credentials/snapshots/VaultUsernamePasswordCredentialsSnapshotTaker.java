package com.datapipe.jenkins.vault.credentials.snapshots;

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import com.datapipe.jenkins.vault.credentials.SecretSnapshot;
import com.datapipe.jenkins.vault.credentials.common.VaultUsernamePasswordCredentialImpl;
import hudson.util.Secret;

public class VaultUsernamePasswordCredentialsSnapshotTaker extends CredentialsSnapshotTaker<VaultUsernamePasswordCredentialImpl> {

    @Override
    public Class<VaultUsernamePasswordCredentialImpl> type() {
        return VaultUsernamePasswordCredentialImpl.class;
    }

    @Override
    public VaultUsernamePasswordCredentialImpl snapshot(
        VaultUsernamePasswordCredentialImpl credential) {
        SecretSnapshot usernameSnapshot = new SecretSnapshot(Secret.fromString(credential.getUsername()));
        SecretSnapshot passwordSnapshot = new SecretSnapshot(credential.getPassword());
        return new VaultUsernamePasswordCredentialImpl(credential.getScope(), credential.getId(), credential.getDescription(), usernameSnapshot, passwordSnapshot);
    }
}
