package com.datapipe.jenkins.vault.credentials.common;

import com.datapipe.jenkins.vault.exception.VaultPluginException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link VaultPKICredentialsImpl}.
 *
 * <p>These tests verify the private key parsing logic and value-object behaviour without
 * requiring a running Vault instance.  The {@code buildKeyStore} integration path (which requires
 * a real X.509 certificate) is exercised at the IT-test level.</p>
 */
public class VaultPKICredentialsImplTest {

    // ---- parsePrivateKey – PKCS#8 RSA (default Vault output) -----------------

    @Test
    public void parsePrivateKey_pkcs8Rsa_returnsRsaKey() throws Exception {
        KeyPair kp = generateRsaKeyPair();
        String pem = pkcs8Pem(kp.getPrivate());

        PrivateKey parsed = VaultPKICredentialsImpl.parsePrivateKey(pem);

        assertNotNull(parsed);
        assertEquals("RSA", parsed.getAlgorithm());
    }

    // ---- parsePrivateKey – PKCS#1 RSA (legacy Vault / custom config) ----------

    @Test
    public void parsePrivateKey_pkcs1RsaHeader_triggersWrapperPath() throws Exception {
        // Build a PKCS#1-labelled PEM from PKCS#8 DER bytes.
        // The raw DER for a PKCS#8 RSA key contains the PKCS#1 structure nested inside it;
        // our wrapper adds a PKCS#8 shell, so passing PKCS#8 bytes with a PKCS#1 header
        // exercises the error-handling of the wrapping path (double-wrapping fails gracefully).
        KeyPair kp = generateRsaKeyPair();
        String fakeRsaPem = "-----BEGIN RSA PRIVATE KEY-----\n"
            + Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(kp.getPrivate().getEncoded())
            + "\n-----END RSA PRIVATE KEY-----";

        // We expect either success (if the JVM accepts it) or a VaultPluginException with a
        // clear message – never a NullPointerException or ClassCastException.
        try {
            PrivateKey key = VaultPKICredentialsImpl.parsePrivateKey(fakeRsaPem);
            assertNotNull(key);
        } catch (VaultPluginException e) {
            assertTrue("Exception message should mention RSA or PKCS#1",
                e.getMessage().contains("RSA") || e.getMessage().contains("PKCS"));
        }
    }

    // ---- parsePrivateKey – unsupported formats --------------------------------

    @Test
    public void parsePrivateKey_ecSec1Format_throwsDescriptiveException() {
        String pem = "-----BEGIN EC PRIVATE KEY-----\nZmFrZWtleWRhdGE=\n-----END EC PRIVATE KEY-----";

        VaultPluginException ex = assertThrows(VaultPluginException.class,
            () -> VaultPKICredentialsImpl.parsePrivateKey(pem));

        assertTrue("Exception message should mention SEC1 or EC",
            ex.getMessage().contains("SEC1") || ex.getMessage().contains("EC"));
    }

    @Test
    public void parsePrivateKey_unknownPemType_throwsDescriptiveException() {
        String pem = "-----BEGIN UNKNOWN TYPE-----\nZmFrZWtleWRhdGE=\n-----END UNKNOWN TYPE-----";

        VaultPluginException ex = assertThrows(VaultPluginException.class,
            () -> VaultPKICredentialsImpl.parsePrivateKey(pem));

        assertTrue("Exception message should mention 'Unrecognised'",
            ex.getMessage().contains("Unrecognised"));
    }

    // ---- IssuedCertificate value object ----------------------------------------

    @Test
    public void issuedCertificate_storesAllFieldsConsistently() {
        VaultPKICredentialsImpl.IssuedCertificate issued =
            new VaultPKICredentialsImpl.IssuedCertificate(
                "cert-pem", "key-pem", "ca-pem", "lease-abc-123", "ks-pass");

        assertEquals("cert-pem", issued.certificatePem);
        assertEquals("key-pem", issued.privateKeyPem);
        assertEquals("ca-pem", issued.issuingCaPem);
        assertEquals("lease-abc-123", issued.leaseId);
        assertEquals("ks-pass", issued.keystorePassword);
    }

    // ---- VaultPKICredentialsImpl field defaults --------------------------------

    @Test
    public void getPkiMount_returnsDefaultWhenNotSet() {
        VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(null, "test-id", "desc");
        assertEquals(VaultPKICredentialsImpl.DEFAULT_PKI_MOUNT, cred.getPkiMount());
    }

    @Test
    public void getTtl_returnsDefaultWhenNotSet() {
        VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(null, "test-id", "desc");
        assertEquals(VaultPKICredentialsImpl.DEFAULT_TTL, cred.getTtl());
    }

    @Test
    public void issueCertificate_blankRole_throwsDescriptiveException() {
        VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(null, "test-id", "desc");
        cred.setCommonName("jenkins.example.com");
        // pkiRole is blank

        VaultPluginException ex = assertThrows(VaultPluginException.class, cred::getKeyStore);
        assertTrue("Exception message should mention pkiRole",
            ex.getMessage().contains("pkiRole"));
    }

    @Test
    public void issueCertificate_blankCommonName_throwsDescriptiveException() {
        VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(null, "test-id", "desc");
        cred.setPkiRole("jenkins");
        // commonName is blank

        VaultPluginException ex = assertThrows(VaultPluginException.class, cred::getKeyStore);
        assertTrue("Exception message should mention commonName",
            ex.getMessage().contains("commonName"));
    }

    // ---- helpers ---------------------------------------------------------------

    private KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    /**
     * Encodes a private key in PKCS#8 PEM format, as Vault PKI returns by default.
     */
    private String pkcs8Pem(PrivateKey key) {
        return "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded())
            + "\n-----END PRIVATE KEY-----";
    }
}
