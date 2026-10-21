package com.datapipe.jenkins.vault.credentials.common;

import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Immutable PEM material of a single Vault PKI issuance.
 *
 * <p>Certificate, private key and CA certificates always originate from the same Vault
 * {@code /issue} response, so consumers never combine a certificate with the private key of a
 * different issuance (which could otherwise happen when the cached certificate is renewed
 * between two separate getter calls).</p>
 */
public final class VaultPKICertificateBundle {

    private static final Base64.Encoder PEM_ENCODER =
        Base64.getMimeEncoder(64, new byte[]{'\n'});

    private final String certificatePem;
    private final Secret privateKeyPem;
    private final String issuingCaPem;
    private final String caChainPem;

    public VaultPKICertificateBundle(@NonNull String certificatePem, @NonNull Secret privateKeyPem,
        @NonNull String issuingCaPem, @NonNull String caChainPem) {
        this.certificatePem = certificatePem;
        this.privateKeyPem = privateKeyPem;
        this.issuingCaPem = issuingCaPem;
        this.caChainPem = caChainPem;
    }

    /** PEM-encoded leaf certificate. */
    @NonNull
    public String getCertificatePem() {
        return certificatePem;
    }

    /**
     * PEM-encoded client certificate chain: the leaf certificate followed by the intermediate
     * CA certificates of {@link #getCaChainPem()}, without the self-signed root.
     *
     * <p>This is what TLS clients (curl, Docker, Go, Python, ...) expect in the client
     * certificate file: with an intermediate CA they must present the intermediates themselves,
     * because a server that only trusts the root cannot build the path otherwise.  For a root
     * CA setup the result is the leaf certificate alone.</p>
     *
     * @throws VaultPluginException if the CA chain returned by Vault cannot be parsed
     */
    @NonNull
    public String getCertificateChainPem() {
        StringBuilder chain = new StringBuilder(certificatePem.trim()).append('\n');
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (Certificate ca : cf.generateCertificates(
                new ByteArrayInputStream(caChainPem.getBytes(StandardCharsets.UTF_8)))) {
                if (!isSelfSigned((X509Certificate) ca)) {
                    chain.append("-----BEGIN CERTIFICATE-----\n")
                        .append(PEM_ENCODER.encodeToString(ca.getEncoded()))
                        .append("\n-----END CERTIFICATE-----\n");
                }
            }
        } catch (CertificateException e) {
            throw new VaultPluginException(
                "Could not parse the CA chain returned by Vault: " + e.getMessage(), e);
        }
        return chain.toString();
    }

    private static boolean isSelfSigned(X509Certificate cert) {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return false;
        }
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** PEM-encoded private key of the leaf certificate. */
    @NonNull
    public Secret getPrivateKeyPem() {
        return privateKeyPem;
    }

    /** PEM-encoded direct issuer certificate ({@code issuing_ca}). */
    @NonNull
    public String getIssuingCaPem() {
        return issuingCaPem;
    }

    /** PEM-encoded CA chain ({@code ca_chain}), or the issuing CA for a root CA setup. */
    @NonNull
    public String getCaChainPem() {
        return caChainPem;
    }
}
