package com.datapipe.jenkins.vault.configuration;

import javax.annotation.Nonnull;

import jenkins.model.GlobalConfiguration;

import java.util.ArrayList;
import java.util.List;

public class GlobalVaultConfiguration extends GlobalConfiguration {
   public static @Nonnull GlobalVaultConfiguration get() {
      GlobalVaultConfiguration instance = GlobalConfiguration.all().get(GlobalVaultConfiguration.class);
      if (instance == null) {
         throw new IllegalStateException();
      }
      return instance;
   }

    private VaultConfiguration configuration;

    public GlobalVaultConfiguration() {
        load();
    }

    public List<VaultConfiguration> getLibraries() {
        return configuration;
    }

    public void setConfiguration(VaultConfiguration configuration) {
        this.configuration = configuration;
        save();
    }
}
