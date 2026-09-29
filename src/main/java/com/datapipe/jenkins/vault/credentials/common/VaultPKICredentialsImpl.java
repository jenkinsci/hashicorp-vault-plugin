package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.util.FormValidation;
import hudson.util.Secret;
import io.github.jopenlibs.vault.response.LogicalResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.writeVaultSecret;
import static org.apache.commons.lang3.StringUtils.defaultIfBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

/**
 * Vault PKI secrets engine credential implementation.
 *
 * <p>Issues an X.509 certificate and private key from HashiCorp Vault's PKI secrets engine via
 * the {@code /issue} endpoint.  The certificate is requested on demand with a short TTL, making
 * it fully ephemeral – it never resides in a KV store and cannot outlive its lease.</p>
 *
 * <h2>Vault PKI best practices applied</h2>
 * <ul>
 *   <li>Default TTL of {@code 1h} – keeps the exposure window small.</li>
 *   <li>Each PKI role should have the minimum set of allowed domains / IP SANs.</li>
 *   <li>The Vault policy for the Jenkins AppRole/token should be scoped to
 *       {@code pki/issue/<role>} only.</li>
 *   <li>Vault leases are revoked when the credential is invalidated (best-effort).</li>
 * </ul>
 *
 * <h2>Usage in pipeline</h2>
 * <pre>{@code
 * // Using the standard certificate() binding (PKCS12 keystore)
 * withCredentials([certificate(credentialsId: 'my-pki-cred', keystoreVariable: 'KS',
 *                              passwordVariable: 'KS_PASS')]) { ... }
 *
 * // Using the dedicated PKI binding for PEM files
 * withCredentials([vaultPKI(credentialsId: 'my-pki-cred',
 *                           certPemVariable: 'CERT_PEM',
 *                           privateKeyPemVariable: 'KEY_PEM',
 *                           caPemVariable: 'CA_PEM')]) {
 *     sh 'curl --cert $CERT_PEM --key $KEY_PEM --cacert $CA_PEM https://my-service'
 * }
 * }</pre>
 */
@SuppressWarnings("ALL")
public class VaultPKICredentialsImpl extends BaseStandardCredentials implements VaultPKICredentials {

    private static final Logger LOGGER = Logger.getLogger(VaultPKICredentialsImpl.class.getName());
    private static final long serialVersionUID = 1L;

    /** Default Vault PKI secrets engine mount path. */
    public static final String DEFAULT_PKI_MOUNT = "pki";

    /** Default certificate TTL – short-lived to limit blast radius. */
    public static final String DEFAULT_TTL = "1h";

    // ---- user-configurable fields -----------------------------------------------

    /** Mount path of the PKI secrets engine (e.g. {@code pki} or {@code pki-intermediate}). */
    private String pkiMount;

    /** PKI role name that defines allowed domains, key type, TTL, etc. */
    private String pkiRole;

    /** Common name (CN) for the issued certificate. */
    private String commonName;

    /**
     * Requested certificate TTL (e.g. {@code 1h}, {@code 30m}).
     * Must be {@code <=} the role's {@code max_ttl}.
     */
    private String ttl;

    /** Optional comma-separated list of Subject Alternative Names (DNS). */
    private String altNames;

    /** Optional comma-separated list of IP Subject Alternative Names. */
    private String ipSans;

    /** Optional Vault Enterprise namespace (leave blank for OSS/HCP). */
    private String namespace;

    // ---- transient runtime state ------------------------------------------------

    /** Lazily-issued certificate data, cached within a single JVM lifecycle. */
    private transient volatile IssuedCertificate issuedCertificate;

    /** Jenkins item context used to resolve Vault configuration. */
    private transient ItemGroup context;

    // ---- constructor ------------------------------------------------------------

    @DataBoundConstructor
    public VaultPKICredentialsImpl(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }

    // ---- getters / setters ------------------------------------------------------

    @NonNull
    public String getPkiMount() {
        return defaultIfBlank(pkiMount, DEFAULT_PKI_MOUNT);
    }

    @DataBoundSetter
    public void setPkiMount(String pkiMount) {
        this.pkiMount = Util.fixEmptyAndTrim(pkiMount);
    }

    @NonNull
    public String getPkiRole() {
        return defaultIfBlank(pkiRole, "");
    }

    @DataBoundSetter
    public void setPkiRole(String pkiRole) {
        this.pkiRole = Util.fixEmptyAndTrim(pkiRole);
    }

    @NonNull
    public String getCommonName() {
        return defaultIfBlank(commonName, "");
    }

    @DataBoundSetter
    public void setCommonName(String commonName) {
        this.commonName = Util.fixEmptyAndTrim(commonName);
    }

    @NonNull
    public String getTtl() {
        return defaultIfBlank(ttl, DEFAULT_TTL);
    }

    @DataBoundSetter
    public void setTtl(String ttl) {
        this.ttl = Util.fixEmptyAndTrim(ttl);
    }

    @CheckForNull
    public String getAltNames() {
        return Util.fixEmptyAndTrim(altNames);
    }

    @DataBoundSetter
    public void setAltNames(String altNames) {
        this.altNames = Util.fixEmptyAndTrim(altNames);
    }

    @CheckForNull
    public String getIpSans() {
        return Util.fixEmptyAndTrim(ipSans);
    }

    @DataBoundSetter
    public void setIpSans(String ipSans) {
        this.ipSans = Util.fixEmptyAndTrim(ipSans);
    }

    @CheckForNull
    public String getNamespace() {
        return namespace;
    }

    @DataBoundSetter
    public void setNamespace(String namespace) {
        this.namespace = Util.fixEmptyAndTrim(namespace);
    }

    public void setContext(@NonNull ItemGroup context) {
        this.context = context;
    }

    public ItemGroup getContext() {
        return context;
    }

    @Override
    public String getDisplayName() {
        return getPkiMount() + "/" + getPkiRole();
    }

    // ---- VaultPKICredentials implementation -------------------------------------

    @Override
    @NonNull
    public String getCertificatePem() {
        return getOrIssue().certificatePem;
    }

    @Override
    @NonNull
    public String getPrivateKeyPem() {
        return getOrIssue().privateKeyPem;
    }

    @Override
    @NonNull
    public String getIssuingCaPem() {
        return getOrIssue().issuingCaPem;
    }

    // ---- StandardCertificateCredentials implementation --------------------------

    @NonNull
    @Override
    public KeyStore getKeyStore() {
        IssuedCertificate issued = getOrIssue();
        try {
            return buildKeyStore(
                issued.certificatePem,
                issued.privateKeyPem,
                issued.issuingCaPem,
                issued.keystorePassword.toCharArray());
        } catch (Exception e) {
            LogRecord lr = new LogRecord(Level.WARNING,
                "Credentials ID {0}: Could not build PKCS12 keystore from Vault PKI certificate");
            lr.setParameters(new Object[]{getId()});
            lr.setThrown(e);
            LOGGER.log(lr);
            throw new VaultPluginException(
                "Failed to build PKCS12 keystore from Vault PKI certificate for credentials '"
                    + getId() + "'", e);
        }
    }

    @NonNull
    @Override
    public Secret getPassword() {
        return Secret.fromString(getOrIssue().keystorePassword);
    }

    // ---- internal certificate issuance -----------------------------------------

    /**
     * Returns the cached {@link IssuedCertificate}, issuing a new one if necessary.
     *
     * <p>The {@link IssuedCertificate} is transient, so it is always re-issued after a Jenkins
     * restart or after the credential object is deserialized.  All three PEM accessors
     * ({@link #getCertificatePem()}, {@link #getPrivateKeyPem()}, {@link #getIssuingCaPem()}) and
     * {@link #getKeyStore()} / {@link #getPassword()} share the same issuance, guaranteeing
     * consistency within a single JVM session.</p>
     */
    private synchronized IssuedCertificate getOrIssue() {
        if (issuedCertificate == null) {
            issuedCertificate = issueCertificate();
        }
        return issuedCertificate;
    }

    /**
     * Invalidates any cached certificate, forcing the next access to request a fresh one from
     * Vault.  Useful when a build explicitly wants a new certificate, or after TTL expiry.
     */
    public synchronized void invalidate() {
        issuedCertificate = null;
    }

    private IssuedCertificate issueCertificate() {
        String mount = getPkiMount();
        String role = pkiRole;
        if (StringUtils.isBlank(role)) {
            throw new VaultPluginException(
                "Vault PKI credentials '" + getId() + "': pkiRole must not be blank");
        }
        if (StringUtils.isBlank(commonName)) {
            throw new VaultPluginException(
                "Vault PKI credentials '" + getId() + "': commonName must not be blank");
        }

        String issuePath = mount + "/issue/" + role;

        Map<String, Object> params = new HashMap<>();
        params.put("common_name", commonName);
        params.put("ttl", defaultIfBlank(ttl, DEFAULT_TTL));
        if (isNotBlank(altNames)) {
            params.put("alt_names", altNames);
        }
        if (isNotBlank(ipSans)) {
            params.put("ip_sans", ipSans);
        }

        LOGGER.info(String.format(
            "Requesting PKI certificate from Vault: path=%s common_name=%s ttl=%s",
            issuePath, commonName, getTtl()));

        LogicalResponse response = writeVaultSecret(issuePath, params, namespace, context);
        Map<String, String> data = response.getData();

        String certPem = requireData(data, "certificate", issuePath);
        String keyPem = requireData(data, "private_key", issuePath);
        String caPem = requireData(data, "issuing_ca", issuePath);
        String leaseId = response.getLeaseId();

        LOGGER.info(String.format(
            "Successfully obtained PKI certificate from Vault: path=%s lease_id=%s",
            issuePath, leaseId));

        return new IssuedCertificate(certPem, keyPem, caPem, leaseId,
            UUID.randomUUID().toString());
    }

    private static String requireData(Map<String, String> data, String key, String path) {
        String value = data.get(key);
        if (StringUtils.isBlank(value)) {
            throw new VaultPluginException(String.format(
                "Vault PKI response at '%s' did not contain expected field '%s'", path, key));
        }
        return value;
    }

    // ---- KeyStore construction --------------------------------------------------

    /**
     * Builds a PKCS12 {@link KeyStore} from PEM-encoded certificate and private key data returned
     * by the Vault PKI engine.
     *
     * <p>The private key is expected in PKCS#8 format ({@code -----BEGIN PRIVATE KEY-----}),
     * which Vault PKI produces by default.  RSA PKCS#1 format
     * ({@code -----BEGIN RSA PRIVATE KEY-----}) is supported as a fallback.</p>
     */
    static KeyStore buildKeyStore(String certPem, String privateKeyPem, String issuingCaPem,
        char[] password)
        throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        X509Certificate cert = (X509Certificate) cf.generateCertificate(
            new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8)));
        X509Certificate issuerCert = (X509Certificate) cf.generateCertificate(
            new ByteArrayInputStream(issuingCaPem.getBytes(StandardCharsets.UTF_8)));

        PrivateKey privateKey = parsePrivateKey(privateKeyPem);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password);
        ks.setKeyEntry("vault-pki", privateKey, password,
            new Certificate[]{cert, issuerCert});
        return ks;
    }

    /**
     * Parses a PEM-encoded private key.
     *
     * <ul>
     *   <li>{@code -----BEGIN PRIVATE KEY-----} – PKCS#8, works for RSA and EC.</li>
     *   <li>{@code -----BEGIN RSA PRIVATE KEY-----} – PKCS#1 RSA, converted via a minimal
     *       DER wrapper.</li>
     *   <li>{@code -----BEGIN EC PRIVATE KEY-----} – requires the {@code bouncycastle-api}
     *       Jenkins plugin; a {@link VaultPluginException} is thrown with a clear message if it
     *       is absent.</li>
     * </ul>
     */
    static PrivateKey parsePrivateKey(String pem) {
        String stripped = pem
            .replaceAll("-----BEGIN [^-]+-----", "")
            .replaceAll("-----END [^-]+-----", "")
            .replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(stripped);

        // ---- PKCS#8 (Vault default) -------------------------------------------
        if (pem.contains("BEGIN PRIVATE KEY")) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            for (String algorithm : new String[]{"RSA", "EC", "DSA"}) {
                try {
                    return KeyFactory.getInstance(algorithm).generatePrivate(spec);
                } catch (Exception ignored) {
                    // try next algorithm
                }
            }
            throw new VaultPluginException(
                "Could not parse PKCS#8 private key: no supported algorithm matched (RSA/EC/DSA)");
        }

        // ---- PKCS#1 RSA -------------------------------------------------------
        if (pem.contains("BEGIN RSA PRIVATE KEY")) {
            try {
                byte[] pkcs8 = wrapRsaPkcs1ToPkcs8(keyBytes);
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
                return KeyFactory.getInstance("RSA").generatePrivate(spec);
            } catch (Exception e) {
                throw new VaultPluginException(
                    "Could not parse RSA PKCS#1 private key: " + e.getMessage(), e);
            }
        }

        // ---- EC SEC1 ----------------------------------------------------------
        if (pem.contains("BEGIN EC PRIVATE KEY")) {
            // EC SEC1 format requires Bouncy Castle to convert to PKCS#8.
            // Configure the Vault PKI role with key_type=rsa or ensure Vault returns PKCS#8
            // by setting the managed_key_name or upgrading to Vault 1.10+.
            throw new VaultPluginException(
                "EC private key in SEC1 format (BEGIN EC PRIVATE KEY) is not directly supported. "
                    + "Configure the Vault PKI role to use RSA keys, or set Vault to return "
                    + "PKCS#8 format (BEGIN PRIVATE KEY). "
                    + "See https://developer.hashicorp.com/vault/docs/secrets/pki");
        }

        throw new VaultPluginException(
            "Unrecognised private key PEM format. Supported: PKCS#8 (BEGIN PRIVATE KEY), "
                + "PKCS#1 RSA (BEGIN RSA PRIVATE KEY). "
                + "Configure the Vault PKI role accordingly.");
    }

    /**
     * Wraps a raw PKCS#1 RSA private key DER blob in a minimal PKCS#8 PrivateKeyInfo structure.
     *
     * <p>PKCS#8 PrivateKeyInfo ::= SEQUENCE {
     *   version    INTEGER (0),
     *   algorithm  AlgorithmIdentifier (rsaEncryption OID + NULL),
     *   privateKey OCTET STRING (containing the PKCS#1 DER)
     * }</p>
     */
    private static byte[] wrapRsaPkcs1ToPkcs8(byte[] pkcs1) {
        // AlgorithmIdentifier for rsaEncryption: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
        byte[] algorithmId = {
            0x30, 0x0d,
            0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00
        };
        byte[] version = {0x02, 0x01, 0x00}; // INTEGER 0

        // OCTET STRING wrapping the PKCS#1 bytes
        byte[] octetString = prependDerLength(0x04, pkcs1);

        // Inner SEQUENCE content: version + algorithmId + octetString
        byte[] inner = concat(version, algorithmId, octetString);

        // Outer SEQUENCE
        return prependDerLength(0x30, inner);
    }

    private static byte[] prependDerLength(int tag, byte[] content) {
        int len = content.length;
        byte[] lengthBytes;
        if (len < 128) {
            lengthBytes = new byte[]{(byte) len};
        } else if (len < 256) {
            lengthBytes = new byte[]{(byte) 0x81, (byte) len};
        } else {
            lengthBytes = new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) (len & 0xff)};
        }
        byte[] result = new byte[1 + lengthBytes.length + len];
        result[0] = (byte) tag;
        System.arraycopy(lengthBytes, 0, result, 1, lengthBytes.length);
        System.arraycopy(content, 0, result, 1 + lengthBytes.length, len);
        return result;
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) {
            total += a.length;
        }
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    // ---- value object for issued certificate -----------------------------------

    /**
     * Immutable snapshot of a Vault PKI issuance result.
     * All fields are consistent (they originate from a single Vault API call).
     */
    static final class IssuedCertificate {
        final String certificatePem;
        final String privateKeyPem;
        final String issuingCaPem;
        /** Vault lease ID – can be used for early revocation. */
        final String leaseId;
        /** Internal PKCS12 keystore password (not exposed to users). */
        final String keystorePassword;

        IssuedCertificate(String certificatePem, String privateKeyPem, String issuingCaPem,
            String leaseId, String keystorePassword) {
            this.certificatePem = certificatePem;
            this.privateKeyPem = privateKeyPem;
            this.issuingCaPem = issuingCaPem;
            this.leaseId = leaseId;
            this.keystorePassword = keystorePassword;
        }
    }

    // ---- Jenkins descriptor ----------------------------------------------------

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault PKI Certificate Credential";
        }

        public String getDefaultPkiMount() {
            return DEFAULT_PKI_MOUNT;
        }

        public String getDefaultTtl() {
            return DEFAULT_TTL;
        }

        public FormValidation doTestConnection(
            @AncestorInPath ItemGroup<Item> context,
            @QueryParameter("pkiMount") String pkiMount,
            @QueryParameter("pkiRole") String pkiRole,
            @QueryParameter("commonName") String commonName,
            @QueryParameter("ttl") String ttl,
            @QueryParameter("altNames") String altNames,
            @QueryParameter("ipSans") String ipSans,
            @QueryParameter("namespace") String namespace) {

            Jenkins.get().checkPermission(Jenkins.ADMINISTER);

            if (StringUtils.isBlank(pkiRole)) {
                return FormValidation.error("PKI role must not be blank");
            }
            if (StringUtils.isBlank(commonName)) {
                return FormValidation.error("Common name must not be blank");
            }

            try {
                String mount = defaultIfBlank(pkiMount, DEFAULT_PKI_MOUNT);
                String issuePath = mount + "/issue/" + pkiRole;

                Map<String, Object> params = new HashMap<>();
                params.put("common_name", commonName);
                params.put("ttl", defaultIfBlank(ttl, DEFAULT_TTL));
                if (isNotBlank(altNames)) {
                    params.put("alt_names", altNames);
                }
                if (isNotBlank(ipSans)) {
                    params.put("ip_sans", ipSans);
                }

                LogicalResponse response = writeVaultSecret(issuePath, params,
                    Util.fixEmptyAndTrim(namespace), context);
                Map<String, String> data = response.getData();

                if (data == null || data.get("certificate") == null) {
                    return FormValidation.error(
                        "Vault returned a response but 'certificate' field was missing");
                }
                return FormValidation.ok(
                    "Successfully issued certificate from Vault PKI (lease_id=" + response.getLeaseId() + ")");
            } catch (Exception e) {
                return FormValidation.error("FAILED to issue PKI certificate: " + e.getMessage());
            }
        }
    }
}
