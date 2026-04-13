package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;

@NameWith(value = VaultStaticUsernamePasswordCredential.NameProvider.class, priority = 32)
public interface VaultStaticUsernamePasswordCredential extends StandardUsernamePasswordCredentials {

    String getDisplayName();

    class NameProvider extends CredentialsNameProvider<VaultStaticUsernamePasswordCredential> {

        @NonNull
        @Override
        public String getName(VaultStaticUsernamePasswordCredential c) {
            String description = Util.fixEmpty(c.getDescription());
            return c.getDisplayName() + (description == null ? "" : " (" + description + ")");
        }
    }
}
