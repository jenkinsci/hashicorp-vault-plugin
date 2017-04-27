package com.datapipe.jenkins.vault.configuration;

import hudson.ExtensionPoint;
import hudson.model.Item;

import javax.annotation.Nonnull;

public abstract class VaultConfigResolver implements ExtensionPoint {
    public abstract @Nonnull VaultConfiguration forJob(@Nonnull Item job);
}
