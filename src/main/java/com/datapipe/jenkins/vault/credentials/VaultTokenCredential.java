package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import hudson.util.Secret;

import javax.annotation.Nonnull;

@NameWith(VaultTokenCredential.NameProvider.class)
public interface VaultTokenCredential extends StandardCredentials {
    String getRoleId();
    Secret getSecretId();

   class NameProvider extends CredentialsNameProvider<VaultTokenCredential> {

      @Nonnull
      public String getName(@Nonnull VaultTokenCredential credentials) {
         return credentials.getDescription();
      }
   }
}
