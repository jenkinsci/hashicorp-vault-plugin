package com.datapipe.jenkins.vault.credentials;

import javax.annotation.Nonnull;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCredentials;

import hudson.util.Secret;

@NameWith(VaultTokenCredential.NameProvider.class)
public interface VaultTokenCredential extends StandardCredentials {
    String getRoleId();
    Secret getSecretId();

   public static class NameProvider extends CredentialsNameProvider<VaultTokenCredential> {

      @Nonnull
      public String getName(@Nonnull VaultTokenCredential credentials) {
         return credentials.getDescription();
      }
   }
}
