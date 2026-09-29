package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCertificateCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;

/**
 * Vault PKI secrets engine credential.
 *
 * <p>Extends {@link StandardCertificateCredentials} so it integrates transparently with Jenkins'
 * built-in {@code certificate()} credential binding, while also exposing the individual PEM
 * components for use with the dedicated {@link VaultPKICredentialsBinding}.</p>
 *
 * <p>Certificates are issued on demand from the Vault PKI secrets engine with a short TTL,
 * rather than stored as long-lived secrets in a KV engine.  This is the recommended pattern
 * described in the HashiCorp Vault PKI best practices guide.</p>
 */
@NameWith(value = VaultPKICredentials.NameProvider.class, priority = 32)
public interface VaultPKICredentials extends StandardCertificateCredentials {

    /** Human-readable display name (defaults to the PKI mount + role). */
    String getDisplayName();

    /**
     * PEM-encoded X.509 certificate issued by the Vault PKI engine.
     * Consistent with {@link #getPrivateKeyPem()} and {@link #getIssuingCaPem()} –
     * all three originate from the same Vault issuance call.
     *
     * @return PEM string starting with {@code -----BEGIN CERTIFICATE-----}
     */
    String getCertificatePem();

    /**
     * PEM-encoded private key issued by the Vault PKI engine.
     *
     * @return PEM string (PKCS#8 or RSA/EC format depending on Vault configuration)
     */
    String getPrivateKeyPem();

    /**
     * PEM-encoded issuing CA certificate from the Vault PKI engine.
     *
     * @return PEM string starting with {@code -----BEGIN CERTIFICATE-----}
     */
    String getIssuingCaPem();

    class NameProvider extends CredentialsNameProvider<VaultPKICredentials> {
        @NonNull
        @Override
        public String getName(VaultPKICredentials c) {
            String description = Util.fixEmpty(c.getDescription());
            return c.getDisplayName() + (description == null ? "" : " (" + description + ")");
        }
    }
}
