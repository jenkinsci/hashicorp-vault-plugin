package com.datapipe.jenkins.vault.credentials.snapshots;



import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import com.datapipe.jenkins.vault.credentials.SecretSnapshot;
import com.datapipe.jenkins.vault.credentials.common.VaultSSHUserPrivateKeyImpl;
import hudson.util.Secret;
import java.util.logging.Level;
import java.util.logging.Logger;


import static org.apache.commons.lang.StringUtils.defaultIfBlank;

public class VaultSSHUserPrivateKeyCredentialsSnapshotTaker extends CredentialsSnapshotTaker<VaultSSHUserPrivateKeyImpl> {
    private static final Logger LOGGER = Logger
    .getLogger(VaultSSHUserPrivateKeyCredentialsSnapshotTaker.class.getName());

    @Override
    public Class<VaultSSHUserPrivateKeyImpl> type() {
        return VaultSSHUserPrivateKeyImpl.class;
    }

    @Override
    public VaultSSHUserPrivateKeyImpl snapshot(
        VaultSSHUserPrivateKeyImpl credential) {
        LOGGER.log(Level.WARNING, "Creating snapshot for ssh key");
        SecretSnapshot passphrase = new SecretSnapshot(Secret.fromString(credential.getVaultSecretKeyValue(defaultIfBlank(credential.getPassphraseKey(), VaultSSHUserPrivateKeyImpl.DEFAULT_PASSPHRASE_KEY))));
        SecretSnapshot privateKey = new SecretSnapshot(Secret.fromString(credential.getVaultSecretKeyValue(defaultIfBlank(credential.getPrivateKeyKey(), VaultSSHUserPrivateKeyImpl.DEFAULT_PRIVATE_KEY_KEY))));
        SecretSnapshot username = new SecretSnapshot(Secret.fromString(credential.getVaultSecretKeyValue(defaultIfBlank(credential.getUsernameKey(), VaultSSHUserPrivateKeyImpl.DEFAULT_USERNAME_KEY))));
        return new VaultSSHUserPrivateKeyImpl(credential.getScope(), credential.getId(), credential.getDescription(), username, privateKey, passphrase);
    }
}
