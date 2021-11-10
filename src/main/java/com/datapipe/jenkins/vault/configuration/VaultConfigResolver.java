package com.datapipe.jenkins.vault.configuration;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionPoint;
import hudson.model.Item;
import hudson.model.ItemGroup;

public abstract class VaultConfigResolver implements ExtensionPoint {

    @NonNull
    public abstract VaultConfiguration forJob(@NonNull Item job);

    public abstract VaultConfiguration getVaultConfig(@NonNull ItemGroup<Item> itemGroup);
}
