package com.datapipe.jenkins.vault.jcasc.secrets;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;

public interface VaultAuthenticator {
    void authenticate(Vault vault, VaultConfig config) throws VaultException;
    static VaultAuthenticator of(String token) {
        return new VaultSingleTokenAuthenticator(token);
    }
    static VaultAuthenticator of(VaultAppRole appRole, String mountPath) {
        return new VaultAppRoleAuthenticator(appRole, mountPath);
    }
    static VaultAuthenticator of(VaultUsernamePassword vaultUsernamePassword, String mountPath) {
        return new VaultUserPassAuthenticator(vaultUsernamePassword, mountPath);
    }
    static VaultAuthenticator of(VaultKubernetes vaultKubernetes, String mountPath) {
        return new VaultKubernetesAuthenticator(vaultKubernetes, mountPath);
    }
    static VaultAuthenticator of(VaultAwsIam vaultAwsIam, String mountPath) {
        return new VaultAwsIamAuthenticator(vaultAwsIam, mountPath);
    }
}
