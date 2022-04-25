package com.datapipe.jenkins.vault.credentials;

import hudson.util.Secret;

public class SecretSnapshot extends Snapshot<Secret> {

    public SecretSnapshot(Secret value) {
        super(value);
    }
}
