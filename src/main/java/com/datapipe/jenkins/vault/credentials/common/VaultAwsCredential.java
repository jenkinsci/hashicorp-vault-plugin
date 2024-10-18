package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;

@NameWith(value = VaultAwsCredential.NameProvider.class, priority = 32)
public interface VaultAwsCredential extends AmazonWebServicesCredentials {

    String getDisplayName();

    class NameProvider extends CredentialsNameProvider<VaultAwsCredential> {

        @NonNull
        @Override
        public String getName(VaultAwsCredential hashicorpVaultCredentials) {
            String description = Util.fixEmpty(hashicorpVaultCredentials.getDescription());
            return hashicorpVaultCredentials.getDisplayName() + (description == null ? ""
                    : " (" + description + ")");
        }
    }
}
