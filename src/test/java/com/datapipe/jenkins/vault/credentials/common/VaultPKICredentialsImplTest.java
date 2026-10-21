package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import hudson.util.Secret;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.json.Json;
import io.github.jopenlibs.vault.json.JsonArray;
import io.github.jopenlibs.vault.json.JsonObject;
import io.github.jopenlibs.vault.json.JsonValue;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
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
    public void parsePrivateKey_genuinePkcs1Rsa_matchesPkcs8Encoding() throws Exception {
        PrivateKey fromPkcs1 = VaultPKICredentialsImpl.parsePrivateKey(fixture("leaf-key-pkcs1.pem"));
        PrivateKey fromPkcs8 = VaultPKICredentialsImpl.parsePrivateKey(fixture("leaf-key-pkcs8.pem"));

        assertEquals("RSA", fromPkcs1.getAlgorithm());
        assertArrayEquals("PKCS#1 and PKCS#8 encodings must yield the same key",
            fromPkcs8.getEncoded(), fromPkcs1.getEncoded());
    }

    // ---- parsePrivateKey – unsupported formats --------------------------------

    @Test
    public void parsePrivateKey_pkcs8Ec_returnsEcKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(256);
        KeyPair kp = gen.generateKeyPair();

        PrivateKey parsed = VaultPKICredentialsImpl.parsePrivateKey(pkcs8Pem(kp.getPrivate()));

        assertEquals("EC", parsed.getAlgorithm());
        assertArrayEquals(kp.getPrivate().getEncoded(), parsed.getEncoded());
    }

    // ---- issue request parameters ----------------------------------------------

    @Test
    public void buildIssueParams_requestsPkcs8PrivateKeys() {
        Map<String, Object> params = VaultPKICredentialsImpl.buildIssueParams(
            "jenkins.example.com", "15m", "a.example.com", "10.0.0.1");

        // without it Vault returns EC keys as SEC1, which the keystore parser rejects
        assertEquals("pkcs8", params.get("private_key_format"));
        assertEquals("jenkins.example.com", params.get("common_name"));
        assertEquals("15m", params.get("ttl"));
        assertEquals("a.example.com", params.get("alt_names"));
        assertEquals("10.0.0.1", params.get("ip_sans"));
    }

    @Test
    public void buildIssueParams_optionalFieldsOmittedAndDefaultTtl() {
        Map<String, Object> params = VaultPKICredentialsImpl.buildIssueParams(
            "jenkins.example.com", null, null, " ");

        assertEquals("pkcs8", params.get("private_key_format"));
        assertEquals(VaultPKICredentialsImpl.DEFAULT_TTL, params.get("ttl"));
        assertTrue(!params.containsKey("alt_names") && !params.containsKey("ip_sans"));
    }

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
        Instant renewAfter = Instant.now().plusSeconds(3540);
        VaultPKICertificateBundle bundle = new VaultPKICertificateBundle(
            "cert-pem", Secret.fromString("key-pem"), "ca-pem", "ca-chain-pem");
        VaultPKICredentialsImpl.IssuedCertificate issued =
            new VaultPKICredentialsImpl.IssuedCertificate(
                bundle, Secret.fromString("lease-abc-123"), renewAfter);

        assertEquals("cert-pem", issued.bundle.getCertificatePem());
        assertEquals("key-pem", issued.bundle.getPrivateKeyPem().getPlainText());
        assertEquals("ca-pem", issued.bundle.getIssuingCaPem());
        assertEquals("ca-chain-pem", issued.bundle.getCaChainPem());
        assertEquals("lease-abc-123", issued.leaseId.getPlainText());
        assertEquals(renewAfter, issued.renewAfter);
    }

    // ---- buildKeyStore – full intermediate/root chain --------------------------

    @Test
    public void buildKeyStore_intermediateChain_storesOrderedChainWithMatchingKey() throws Exception {
        char[] password = "changeit".toCharArray();
        KeyStore ks = VaultPKICredentialsImpl.buildKeyStore(fixture("leaf.pem"),
            fixture("leaf-key-pkcs8.pem"), fixture("ca-chain.pem"), password);

        assertTrue(ks.isKeyEntry("vault-pki"));
        Certificate[] chain = ks.getCertificateChain("vault-pki");
        assertEquals("leaf, intermediate and root expected", 3, chain.length);
        assertEquals(subject("leaf.pem"), ((X509Certificate) chain[0]).getSubjectX500Principal());
        assertEquals(subject("intermediate.pem"),
            ((X509Certificate) chain[1]).getSubjectX500Principal());
        assertEquals(subject("root.pem"), ((X509Certificate) chain[2]).getSubjectX500Principal());
        // each certificate must be signed by the next one in the chain
        chain[0].verify(chain[1].getPublicKey());
        chain[1].verify(chain[2].getPublicKey());
        chain[2].verify(chain[2].getPublicKey());

        // the stored private key must belong to the leaf certificate
        PrivateKey key = (PrivateKey) ks.getKey("vault-pki", password);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(new byte[]{1, 2, 3});
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(chain[0].getPublicKey());
        verifier.update(new byte[]{1, 2, 3});
        assertTrue("private key does not match the leaf certificate", verifier.verify(signature));
    }

    @Test
    public void buildKeyStore_rootOnlyChain_storesLeafAndIssuer() throws Exception {
        KeyStore ks = VaultPKICredentialsImpl.buildKeyStore(fixture("leaf.pem"),
            fixture("leaf-key-pkcs1.pem"), fixture("intermediate.pem"), "changeit".toCharArray());

        assertEquals(2, ks.getCertificateChain("vault-pki").length);
    }

    // ---- Vault issue response: ca_chain extraction ------------------------------

    @Test
    public void fromResponse_intermediateCaChainArray_buildsCompleteBundle() throws Exception {
        LogicalResponse response = issueResponse(new JsonArray()
            .add(fixture("intermediate.pem")).add(fixture("root.pem")));
        Instant issuedAt = Instant.now();

        VaultPKICredentialsImpl.IssuedCertificate issued =
            VaultPKICredentialsImpl.fromResponse(response, "pki-int/issue/jenkins", issuedAt);

        VaultPKICertificateBundle bundle = issued.bundle;
        assertEquals(fixture("leaf.pem"), bundle.getCertificatePem());
        assertEquals(fixture("leaf-key-pkcs8.pem"), bundle.getPrivateKeyPem().getPlainText());
        assertEquals(fixture("intermediate.pem"), bundle.getIssuingCaPem());
        assertEquals("ca_chain must contain intermediate and root in Vault's order",
            fixture("intermediate.pem").trim() + "\n" + fixture("root.pem").trim(),
            bundle.getCaChainPem());
        assertEquals(2, parseCertificates(bundle.getCaChainPem()).size());
        assertEquals("client chain: leaf + intermediate",
            2, parseCertificates(bundle.getCertificateChainPem()).size());
        assertEquals("lease-123", issued.leaseId.getPlainText());
        assertTrue(issued.renewAfter.isAfter(issuedAt));
    }

    @Test
    public void extractCaChain_absentField_fallsBackToIssuingCa() throws Exception {
        assertCaChainFallsBack(issueResponse(null));
    }

    @Test
    public void extractCaChain_nullField_fallsBackToIssuingCa() throws Exception {
        assertCaChainFallsBack(issueResponse(Json.NULL));
    }

    @Test
    public void extractCaChain_emptyArray_fallsBackToIssuingCa() throws Exception {
        assertCaChainFallsBack(issueResponse(new JsonArray()));
    }

    @Test
    public void extractCaChain_notAnArray_fallsBackToIssuingCa() throws Exception {
        assertCaChainFallsBack(issueResponse(Json.value(fixture("root.pem"))));
    }

    @Test
    public void extractCaChain_arrayWithNonStringEntries_fallsBackToIssuingCa() throws Exception {
        assertCaChainFallsBack(issueResponse(new JsonArray().add(42).add(true)));
    }

    @Test
    public void extractCaChain_arrayWithOnlyBlankEntries_fallsBackToIssuingCa() throws Exception {
        assertCaChainFallsBack(issueResponse(new JsonArray().add("").add("  ")));
    }

    @Test
    public void fromResponse_missingPrivateKey_throwsDescriptiveException() throws Exception {
        JsonObject data = Json.object()
            .add("certificate", fixture("leaf.pem"))
            .add("issuing_ca", fixture("intermediate.pem"));
        LogicalResponse response = response(200, Json.object().add("data", data).toString());

        VaultPluginException ex = assertThrows(VaultPluginException.class,
            () -> VaultPKICredentialsImpl.fromResponse(response, "pki-int/issue/jenkins",
                Instant.now()));
        assertTrue(ex.getMessage(), ex.getMessage().contains("private_key"));
    }

    private static void assertCaChainFallsBack(LogicalResponse response) throws Exception {
        assertEquals(fixture("intermediate.pem"),
            VaultPKICredentialsImpl.extractCaChain(response, fixture("intermediate.pem")));
        assertEquals(fixture("intermediate.pem"), VaultPKICredentialsImpl.fromResponse(
            response, "pki-int/issue/jenkins", Instant.now()).bundle.getCaChainPem());
    }

    /** A Vault {@code /issue} response as returned by Vault; {@code caChain == null} omits it. */
    private static LogicalResponse issueResponse(JsonValue caChain) throws Exception {
        JsonObject data = Json.object()
            .add("certificate", fixture("leaf.pem"))
            .add("private_key", fixture("leaf-key-pkcs8.pem"))
            .add("private_key_type", "rsa")
            .add("issuing_ca", fixture("intermediate.pem"))
            .add("serial_number", "39:dd:2e");
        if (caChain != null) {
            data.add("ca_chain", caChain);
        }
        JsonObject body = Json.object()
            .add("lease_id", "lease-123")
            .add("renewable", false)
            .add("lease_duration", 0)
            .add("data", data);
        return response(200, body.toString());
    }

    // ---- VaultPKICertificateBundle#getCertificateChainPem ------------------------

    @Test
    public void certificateChainPem_intermediateSetup_containsLeafAndIntermediateButNotRoot()
        throws Exception {
        VaultPKICertificateBundle bundle = new VaultPKICertificateBundle(fixture("leaf.pem"),
            Secret.fromString(fixture("leaf-key-pkcs8.pem")), fixture("intermediate.pem"),
            fixture("ca-chain.pem"));

        List<X509Certificate> chain = parseCertificates(bundle.getCertificateChainPem());

        assertEquals("leaf followed by the intermediate", 2, chain.size());
        assertEquals(subject("leaf.pem"), chain.get(0).getSubjectX500Principal());
        assertEquals(subject("intermediate.pem"), chain.get(1).getSubjectX500Principal());
        chain.get(0).verify(chain.get(1).getPublicKey());
    }

    @Test
    public void certificateChainPem_rootOnlySetup_containsOnlyLeaf() throws Exception {
        // Root CA setup: the issuing CA is the self-signed root, which a client never sends
        VaultPKICertificateBundle bundle = new VaultPKICertificateBundle(fixture("intermediate.pem"),
            Secret.fromString("unused"), fixture("root.pem"), fixture("root.pem"));

        List<X509Certificate> chain = parseCertificates(bundle.getCertificateChainPem());

        assertEquals(1, chain.size());
        assertEquals(subject("intermediate.pem"), chain.get(0).getSubjectX500Principal());
    }

    @Test
    public void certificateChainPem_unparsableCaChain_throwsDescriptiveException() throws Exception {
        VaultPKICertificateBundle bundle = new VaultPKICertificateBundle(fixture("leaf.pem"),
            Secret.fromString("unused"), "garbage", "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----");

        VaultPluginException ex = assertThrows(VaultPluginException.class,
            bundle::getCertificateChainPem);
        assertTrue(ex.getMessage(), ex.getMessage().contains("CA chain"));
    }

    // ---- computeRenewAfter -------------------------------------------------------

    @Test
    public void computeRenewAfter_regularLifetime_renewsAfterHalfTheLifetime() {
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        Instant notAfter = issuedAt.plus(Duration.ofHours(1));

        assertEquals(issuedAt.plus(Duration.ofMinutes(30)),
            VaultPKICredentialsImpl.computeRenewAfter(issuedAt, notAfter));
    }

    @Test
    public void computeRenewAfter_shortLifetime_staysBetweenIssuanceAndExpiry() {
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        Instant notAfter = issuedAt.plusSeconds(40);

        Instant renewAfter = VaultPKICredentialsImpl.computeRenewAfter(issuedAt, notAfter);

        assertEquals(issuedAt.plusSeconds(20), renewAfter);
        assertTrue(renewAfter.isAfter(issuedAt));
        assertTrue(renewAfter.isBefore(notAfter));
    }

    @Test
    public void computeRenewAfter_alreadyExpired_renewsImmediately() {
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");

        assertEquals(issuedAt,
            VaultPKICredentialsImpl.computeRenewAfter(issuedAt, issuedAt.minusSeconds(5)));
    }

    // ---- shared certificate cache ------------------------------------------------

    @Test
    public void cachedCertificate_laterBuildNeverGetsLessThanHalfTheTtl() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CountingCredentials cred = new CountingCredentials(Duration.ofHours(1));
        cred.setClock(clock);

        VaultPKICertificateBundle first = cred.getCertificateBundle();
        assertEquals(1, cred.issued);

        // a build 29 minutes later still shares the cached certificate (31 minutes left)
        clock.advance(Duration.ofMinutes(29));
        assertSame(first, cred.getCertificateBundle());
        assertEquals(1, cred.issued);

        // a build 58 minutes after issuance must not get the old certificate with 2 minutes left
        clock.advance(Duration.ofMinutes(29));
        VaultPKICertificateBundle later = cred.getCertificateBundle();
        assertNotSame("nearly expired certificate must not be handed out", first, later);
        assertEquals(2, cred.issued);
        assertEquals("the later build gets the full TTL",
            clock.instant().plus(Duration.ofHours(1)), cred.notAfterOf(later));
    }

    @Test
    public void cachedCertificate_remainingLifetimeAlwaysAtLeastHalfTheTtl() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CountingCredentials cred = new CountingCredentials(Duration.ofHours(1));
        cred.setClock(clock);

        for (int minute = 0; minute <= 180; minute++) {
            VaultPKICertificateBundle bundle = cred.getCertificateBundle();
            Duration remaining = Duration.between(clock.instant(), cred.notAfterOf(bundle));
            assertTrue("only " + remaining + " left at minute " + minute,
                remaining.compareTo(Duration.ofMinutes(30)) >= 0);
            clock.advance(Duration.ofMinutes(1));
        }
        assertEquals("renewed every 30 minutes over 3 hours", 7, cred.issued);
    }

    @Test
    public void forRun_default_sharesTheCachedCertificateBetweenBuilds() {
        CountingCredentials cred = new CountingCredentials(Duration.ofHours(1));

        VaultPKICredentials build1 = (VaultPKICredentials) cred.forRun(null);
        VaultPKICredentials build2 = (VaultPKICredentials) cred.forRun(null);

        assertSame(cred, build1);
        assertSame(build1.getCertificateBundle(), build2.getCertificateBundle());
        assertEquals(1, cred.issued);
    }

    @Test
    public void forRun_issuePerBuild_givesEveryBuildItsOwnCertificate() {
        CountingCredentials cred = new CountingCredentials(Duration.ofHours(1));
        cred.setIssuePerBuild(true);

        VaultPKICredentials build1 = (VaultPKICredentials) cred.forRun(null);
        VaultPKICredentials build2 = (VaultPKICredentials) cred.forRun(null);

        assertNotSame(build1, build2);
        VaultPKICertificateBundle bundle1 = build1.getCertificateBundle();
        VaultPKICertificateBundle bundle2 = build2.getCertificateBundle();
        assertNotSame("builds must not share a certificate", bundle1, bundle2);
        assertEquals(2, cred.issued);
        // within one build the material stays consistent (issued once)
        assertSame(bundle1, build1.getCertificateBundle());
        assertEquals(2, cred.issued);
    }

    @Test
    public void forRun_issuePerBuild_copyKeepsTheConfiguration() {
        VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(CredentialsScope.GLOBAL,
            "pki-id", "pki description");
        cred.setPkiMount("pki-int");
        cred.setPkiRole("jenkins");
        cred.setCommonName("jenkins.example.com");
        cred.setTtl("15m");
        cred.setAltNames("a.example.com");
        cred.setIpSans("10.0.0.1");
        cred.setNamespace("team-a");
        cred.setIssuePerBuild(true);

        VaultPKICredentialsImpl copy = (VaultPKICredentialsImpl) cred.forRun(null);

        assertNotSame(cred, copy);
        assertEquals(cred.getId(), copy.getId());
        assertEquals(cred.getScope(), copy.getScope());
        assertEquals(cred.getDescription(), copy.getDescription());
        assertEquals("pki-int", copy.getPkiMount());
        assertEquals("jenkins", copy.getPkiRole());
        assertEquals("jenkins.example.com", copy.getCommonName());
        assertEquals("15m", copy.getTtl());
        assertEquals("a.example.com", copy.getAltNames());
        assertEquals("10.0.0.1", copy.getIpSans());
        assertEquals("team-a", copy.getNamespace());
        assertTrue(copy.isIssuePerBuild());
        // a fresh instance: its own keystore password, not the original's
        assertNotEquals(cred.getPassword().getPlainText(), copy.getPassword().getPlainText());
    }

    /** Credentials whose issuance is simulated: every issuance gets a new bundle and lifetime. */
    private static final class CountingCredentials extends VaultPKICredentialsImpl {
        private final Duration lifetime;
        private final Map<VaultPKICertificateBundle, Instant> notAfter = new IdentityHashMap<>();
        int issued;

        private final CountingCredentials counter;

        CountingCredentials(Duration lifetime) {
            this(lifetime, null);
        }

        private CountingCredentials(Duration lifetime, CountingCredentials counter) {
            super(null, "counting", "simulated issuance");
            this.lifetime = lifetime;
            this.counter = counter;
        }

        @Override
        VaultPKICredentialsImpl copyWithEmptyCache() {
            CountingCredentials copy = new CountingCredentials(lifetime, this);
            copy.setClock(clock());
            return copy;
        }

        @Override
        IssuedCertificate issueCertificate() {
            CountingCredentials root = counter != null ? counter : this;
            int n = ++root.issued;
            Instant now = clock().instant();
            VaultPKICertificateBundle bundle = new VaultPKICertificateBundle("cert-" + n,
                Secret.fromString("key-" + n), "ca", "ca");
            notAfter.put(bundle, now.plus(lifetime));
            return new IssuedCertificate(bundle, Secret.fromString("lease-" + n),
                computeRenewAfter(now, now.plus(lifetime)));
        }

        Instant notAfterOf(VaultPKICertificateBundle bundle) {
            return notAfter.get(bundle);
        }
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    // ---- buildIssuePath ------------------------------------------------------------

    @Test
    public void buildIssuePath_validMountAndRole_buildsIssuePath() {
        assertEquals("pki-int/issue/jenkins",
            VaultPKICredentialsImpl.buildIssuePath("pki-int", "jenkins"));
        assertEquals("teams/a/pki_v2/issue/web.client",
            VaultPKICredentialsImpl.buildIssuePath("teams/a/pki_v2", "web.client"));
    }

    @Test
    public void buildIssuePath_traversalOrInjection_isRejected() {
        String[][] invalid = {
            {"pki/../sys", "role"}, {"..", "role"}, {"pki/", "role"}, {"/pki", "role"},
            {"pki", "../../sys/policy/x"}, {"pki", "a/b"}, {"pki", ".."}, {"pki", "r?x=1"},
            {"pki", "r#x"}, {"pki", "r%2e%2e"}, {"pki", ""}, {"", "role"}, {null, "role"},
            {"pki", null}
        };
        for (String[] c : invalid) {
            assertThrows("expected rejection of mount=" + c[0] + " role=" + c[1],
                VaultPluginException.class, () -> VaultPKICredentialsImpl.buildIssuePath(c[0], c[1]));
        }
    }

    // ---- keystore password -----------------------------------------------------------

    @Test
    public void getPassword_isStablePerCredentialInstance() {
        VaultPKICredentialsImpl cred = new VaultPKICredentialsImpl(null, "id", "desc");

        assertEquals(cred.getPassword().getPlainText(), cred.getPassword().getPlainText());
        assertNotEquals(cred.getPassword().getPlainText(),
            new VaultPKICredentialsImpl(null, "id2", "desc").getPassword().getPlainText());
    }

    // ---- checkResponseStatus ---------------------------------------------------

    @Test
    public void checkResponseStatus_success_doesNotThrow() {
        VaultPKICredentialsImpl.checkResponseStatus(response(200, "{\"data\":{}}"), "pki/issue/r");
    }

    @Test
    public void checkResponseStatus_vaultError_includesVaultMessage() {
        VaultPluginException ex = assertThrows(VaultPluginException.class,
            () -> VaultPKICredentialsImpl.checkResponseStatus(
                response(400, "{\"errors\":[\"unknown role: nope\"]}"), "pki/issue/nope"));

        assertTrue(ex.getMessage(), ex.getMessage().contains("HTTP 400"));
        assertTrue(ex.getMessage(), ex.getMessage().contains("unknown role: nope"));
    }

    @Test
    public void checkResponseStatus_nonJsonBody_reportsStatusOnly() {
        VaultPluginException ex = assertThrows(VaultPluginException.class,
            () -> VaultPKICredentialsImpl.checkResponseStatus(
                response(503, "<html>unavailable</html>"), "pki/issue/r"));

        assertTrue(ex.getMessage(), ex.getMessage().contains("HTTP 503"));
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

    private static LogicalResponse response(int status, String body) {
        RestResponse rest = new RestResponse(status, "application/json",
            body.getBytes(StandardCharsets.UTF_8));
        return new LogicalResponse(rest, 0, Logical.logicalOperations.writeV1);
    }

    private static String fixture(String name) throws Exception {
        try (InputStream in = VaultPKICredentialsImplTest.class.getResourceAsStream("pki/" + name)) {
            assertNotNull("missing test fixture " + name, in);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static X500Principal subject(String name) throws Exception {
        return ((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
            new ByteArrayInputStream(fixture(name).getBytes(StandardCharsets.UTF_8))))
            .getSubjectX500Principal();
    }

    @SuppressWarnings("unchecked")
    private static List<X509Certificate> parseCertificates(String pem) throws Exception {
        return new ArrayList<>((Collection<X509Certificate>) CertificateFactory.getInstance("X.509")
            .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8))));
    }
}
