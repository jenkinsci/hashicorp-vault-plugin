package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCertificateCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import hudson.util.Secret;

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
     * Use {@link #getCertificateBundle()} when the matching private key is needed as well.
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

    /**
     * Full CA chain PEM returned by the Vault PKI engine ({@code ca_chain} field).
     *
     * <p>When Vault is configured as an <em>intermediate</em> CA the chain contains the
     * intermediate certificate followed by all parent CAs up to (and including) the root.
     * When Vault is a root CA the value equals {@link #getIssuingCaPem()}.</p>
     *
     * <p>Use this value as the trust anchor for {@code openssl verify -CAfile} or mTLS clients
     * so the full chain can be verified without installing the root CA separately.</p>
     *
     * @return concatenated PEM string with one or more {@code -----BEGIN CERTIFICATE-----} blocks
     */
    String getCaChainPem();

    /**
     * Certificate, private key and CA certificates of one single issuance.
     *
     * <p>Prefer this over calling {@link #getCertificatePem()}, {@link #getPrivateKeyPem()} and
     * {@link #getCaChainPem()} one after another: the cached certificate may be renewed between
     * those calls, which would mix material of two different issuances.</p>
     *
     * @return consistent PEM material of a single Vault issuance
     */
    @NonNull
    default VaultPKICertificateBundle getCertificateBundle() {
        return new VaultPKICertificateBundle(getCertificatePem(),
            Secret.fromString(getPrivateKeyPem()), getIssuingCaPem(), getCaChainPem());
    }

    class NameProvider extends CredentialsNameProvider<VaultPKICredentials> {
        @NonNull
        @Override
        public String getName(VaultPKICredentials c) {
            String description = Util.fixEmpty(c.getDescription());
            return c.getDisplayName() + (description == null ? "" : " (" + description + ")");
        }
    }
}
