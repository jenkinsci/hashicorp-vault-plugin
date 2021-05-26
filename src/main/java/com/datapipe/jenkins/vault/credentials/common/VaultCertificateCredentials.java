package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCertificateCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.FilePath;
import hudson.Util;
import java.io.IOException;

@NameWith(value = VaultCertificateCredentials.NameProvider.class, priority = 32)
public interface VaultCertificateCredentials extends StandardCertificateCredentials {

    String getDisplayName();

    class NameProvider extends CredentialsNameProvider<VaultCertificateCredentials> {

        @NonNull
        @Override
        public String getName(VaultCertificateCredentials hashicorpVaultCredentials) {
            String description = Util.fixEmpty(hashicorpVaultCredentials.getDescription());
            return hashicorpVaultCredentials.getDisplayName() + (description == null ? ""
                : " (" + description + ")");
        }
    }

    void write(FilePath keyStoreFile) throws IOException;
}
