package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;

@NameWith(value = VaultGCRLogin.NameProvider.class, priority = 32)
public interface VaultGCRLogin extends VaultUsernamePasswordCredential{

    class NameProvider extends CredentialsNameProvider<VaultGCRLogin> {

        @NonNull
        @Override
        public String getName(VaultGCRLogin hashicorpVaultCredentials) {
            String description = Util.fixEmpty(hashicorpVaultCredentials.getDescription());
            return hashicorpVaultCredentials.getDisplayName() + (description == null ? ""
                : " (" + description + ")");
        }
    }

}
