package com.datapipe.jenkins.vault.exception;

public class VaultPluginException extends RuntimeException {

    public VaultPluginException(String message) {
        super(message);
    }

    public VaultPluginException(String message, Throwable cause) {
        super(message, cause);
    }
}
