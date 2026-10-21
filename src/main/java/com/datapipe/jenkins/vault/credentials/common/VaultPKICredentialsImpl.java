package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.Run;
import hudson.util.FormValidation;
import hudson.util.Secret;
import io.github.jopenlibs.vault.json.Json;
import io.github.jopenlibs.vault.json.JsonArray;
import io.github.jopenlibs.vault.json.JsonObject;
import io.github.jopenlibs.vault.json.JsonValue;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import jenkins.model.Jenkins;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

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
public class VaultPKICredentialsImpl extends BaseStandardCredentials
    implements VaultPKICredentials, VaultContextualCredentials {

    private static final Logger LOGGER = Logger.getLogger(VaultPKICredentialsImpl.class.getName());
    private static final long serialVersionUID = 1L;

    /** Default Vault PKI secrets engine mount path. */
    public static final String DEFAULT_PKI_MOUNT = "pki";

    /** Default certificate TTL – short-lived to limit blast radius. */
    public static final String DEFAULT_TTL = "1h";

    /**
     * One Vault path segment: letters, digits, {@code -} and {@code _}, optionally separated by
     * single dots.  This rules out {@code .} and {@code ..} segments (path traversal).
     */
    private static final String PATH_SEGMENT = "[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+)*";

    /** A PKI mount path: one or more path segments separated by {@code /}. */
    private static final Pattern MOUNT_PATTERN =
        Pattern.compile(PATH_SEGMENT + "(?:/" + PATH_SEGMENT + ")*");

    /** A PKI role name: exactly one path segment. */
    private static final Pattern ROLE_PATTERN = Pattern.compile(PATH_SEGMENT);

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

    /**
     * Issue a separate certificate for every build instead of sharing the cached certificate
     * between builds.  Off by default.
     */
    private boolean issuePerBuild;

    // ---- transient runtime state ------------------------------------------------

    /** Lazily-issued certificate data, cached within a single JVM lifecycle. */
    private transient volatile IssuedCertificate issuedCertificate;

    /** Time source for the cache; only replaced in tests. */
    private transient Clock clock;

    /**
     * Password of the PKCS12 keystore handed out by {@link #getKeyStore()}.  Kept per credential
     * instance (not per issuance) so that {@link #getKeyStore()} and {@link #getPassword()} always
     * match, even if the certificate is renewed between the two calls.
     */
    private transient volatile Secret keystorePassword;

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

    public boolean isIssuePerBuild() {
        return issuePerBuild;
    }

    @DataBoundSetter
    public void setIssuePerBuild(boolean issuePerBuild) {
        this.issuePerBuild = issuePerBuild;
    }

    @Override
    public void setContext(@NonNull ItemGroup context) {
        this.context = context;
    }

    @Override
    public ItemGroup getContext() {
        return context;
    }

    @Override
    public String getDisplayName() {
        return getPkiMount() + "/" + getPkiRole();
    }

    /**
     * Called by the Credentials plugin whenever a build looks up this credential (for both the
     * {@code certificate()} and the {@code vaultPKI()} binding).
     *
     * <p>By default all builds share the cached certificate.  With {@link #isIssuePerBuild()}
     * every lookup gets its own copy with an empty cache, so each build issues its own
     * certificate with the full TTL and no private key is shared with other builds.  Within one
     * binding the copy issues once, so certificate, key and keystore stay consistent.</p>
     */
    @NonNull
    @Override
    public Credentials forRun(@CheckForNull Run<?, ?> run) {
        return issuePerBuild ? copyWithEmptyCache() : this;
    }

    VaultPKICredentialsImpl copyWithEmptyCache() {
        VaultPKICredentialsImpl copy = new VaultPKICredentialsImpl(getScope(), getId(),
            getDescription());
        copy.pkiMount = pkiMount;
        copy.pkiRole = pkiRole;
        copy.commonName = commonName;
        copy.ttl = ttl;
        copy.altNames = altNames;
        copy.ipSans = ipSans;
        copy.namespace = namespace;
        copy.issuePerBuild = issuePerBuild;
        copy.context = context;
        copy.clock = clock;
        return copy;
    }

    // ---- VaultPKICredentials implementation -------------------------------------

    @Override
    @NonNull
    public String getCertificatePem() {
        return getOrIssue().bundle.getCertificatePem();
    }

    @Override
    @NonNull
    public String getPrivateKeyPem() {
        return getOrIssue().bundle.getPrivateKeyPem().getPlainText();
    }

    @Override
    @NonNull
    public String getIssuingCaPem() {
        return getOrIssue().bundle.getIssuingCaPem();
    }

    @Override
    @NonNull
    public String getCaChainPem() {
        return getOrIssue().bundle.getCaChainPem();
    }

    @Override
    @NonNull
    public VaultPKICertificateBundle getCertificateBundle() {
        return getOrIssue().bundle;
    }

    // ---- StandardCertificateCredentials implementation --------------------------

    @NonNull
    @Override
    public KeyStore getKeyStore() {
        VaultPKICertificateBundle bundle = getCertificateBundle();
        try {
            return buildKeyStore(
                bundle.getCertificatePem(),
                bundle.getPrivateKeyPem().getPlainText(),
                bundle.getCaChainPem(),
                getPassword().getPlainText().toCharArray());
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
    public synchronized Secret getPassword() {
        if (keystorePassword == null) {
            keystorePassword = Secret.fromString(UUID.randomUUID().toString());
        }
        return keystorePassword;
    }

    // ---- internal certificate issuance -----------------------------------------

    /**
     * Returns the cached {@link IssuedCertificate}, issuing a new one if necessary.
     *
     * <p>The cached certificate is shared by all builds using this credential.  It is renewed
     * once half of its lifetime has passed (see {@link #computeRenewAfter}), so every build
     * receives a certificate with at least half of the configured TTL left - e.g. at least 30
     * minutes for the default TTL of {@code 1h}.</p>
     */
    private synchronized IssuedCertificate getOrIssue() {
        IssuedCertificate cached = issuedCertificate;
        if (cached == null || !Instant.now(clock()).isBefore(cached.renewAfter)) {
            if (cached != null) {
                LOGGER.info(String.format("Vault PKI credentials '%s': renewing certificate, "
                    + "half of its lifetime has passed", getId()));
            }
            issuedCertificate = issueCertificate();
        }
        return issuedCertificate;
    }

    Clock clock() {
        return clock != null ? clock : Clock.systemUTC();
    }

    /** Test hook: replaces the time source used for cache renewal. */
    void setClock(Clock clock) {
        this.clock = clock;
    }

    /**
     * Invalidates any cached certificate, forcing the next access to request a fresh one from
     * Vault.  Useful when a build explicitly wants a new certificate, or after TTL expiry.
     */
    public synchronized void invalidate() {
        issuedCertificate = null;
    }

    IssuedCertificate issueCertificate() {
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

        String issuePath = buildIssuePath(mount, role);
        Map<String, Object> params = buildIssueParams(commonName, ttl, altNames, ipSans);

        LOGGER.info(String.format(
            "Requesting PKI certificate from Vault: path=%s common_name=%s ttl=%s",
            issuePath, commonName, getTtl()));

        LogicalResponse response = writeVaultSecret(issuePath, params, namespace, context);
        IssuedCertificate issued = fromResponse(response, issuePath, Instant.now(clock()));

        LOGGER.info(String.format(
            "Successfully obtained PKI certificate from Vault: path=%s", issuePath));
        return issued;
    }

    /**
     * Turns the response of {@code <mount>/issue/<role>} into the cached issuance: checks the HTTP
     * status, reads certificate, private key, issuing CA and {@code ca_chain}, and computes when
     * the certificate has to be renewed.
     */
    static IssuedCertificate fromResponse(LogicalResponse response, String issuePath,
        Instant issuedAt) {
        checkResponseStatus(response, issuePath);
        Map<String, String> data = response.getData();

        String certPem = requireData(data, "certificate", issuePath);
        String keyPem = requireData(data, "private_key", issuePath);
        String caPem = requireData(data, "issuing_ca", issuePath);
        String caChainPem = extractCaChain(response, caPem);

        Instant renewAfter = computeRenewAfter(issuedAt, parseCertExpiry(certPem));
        return new IssuedCertificate(
            new VaultPKICertificateBundle(certPem, Secret.fromString(keyPem), caPem, caChainPem),
            Secret.fromString(response.getLeaseId()), renewAfter);
    }

    /**
     * Request body for {@code <mount>/issue/<role>}.
     *
     * <p>{@code private_key_format=pkcs8} makes Vault return the private key as PKCS#8
     * ({@code BEGIN PRIVATE KEY}) for every key type.  Without it Vault returns EC keys in SEC1
     * format ({@code BEGIN EC PRIVATE KEY}), which {@link #parsePrivateKey} cannot read, so EC roles
     * would fail in the {@code certificate()} binding.</p>
     */
    static Map<String, Object> buildIssueParams(String commonName, String ttl, String altNames,
        String ipSans) {
        Map<String, Object> params = new HashMap<>();
        params.put("common_name", commonName);
        params.put("ttl", defaultIfBlank(ttl, DEFAULT_TTL));
        params.put("private_key_format", "pkcs8");
        if (isNotBlank(altNames)) {
            params.put("alt_names", altNames);
        }
        if (isNotBlank(ipSans)) {
            params.put("ip_sans", ipSans);
        }
        return params;
    }

    /**
     * Builds the {@code <mount>/issue/<role>} path after validating both parts, so a crafted
     * mount or role (e.g. containing {@code ..}) cannot redirect the write to another Vault path.
     */
    static String buildIssuePath(String mount, String role) {
        if (mount == null || !MOUNT_PATTERN.matcher(mount).matches()) {
            throw new VaultPluginException("Invalid PKI mount path '" + mount
                + "': use letters, digits, '-', '_' and '.', segments separated by '/'");
        }
        if (role == null || !ROLE_PATTERN.matcher(role).matches()) {
            throw new VaultPluginException("Invalid PKI role name '" + role
                + "': use letters, digits, '-', '_' and '.'");
        }
        return mount + "/issue/" + role;
    }

    /**
     * Point in time after which the cached certificate is renewed: once half of its lifetime
     * ({@code issuedAt} to {@code notAfter}) has passed.  A build that picks up the cached
     * certificate therefore always gets at least half of the lifetime, instead of a certificate
     * that is about to expire.  An already expired certificate is renewed immediately.
     */
    static Instant computeRenewAfter(Instant issuedAt, Instant notAfter) {
        Duration lifetime = Duration.between(issuedAt, notAfter);
        if (lifetime.isNegative() || lifetime.isZero()) {
            return issuedAt;
        }
        return issuedAt.plus(lifetime.dividedBy(2));
    }

    /**
     * Extracts the {@code notAfter} expiry from a PEM-encoded X.509 certificate.
     * Falls back to 30 minutes from now if the certificate cannot be parsed.
     */
    private static Instant parseCertExpiry(String certPem) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8)));
            return cert.getNotAfter().toInstant();
        } catch (Exception e) {
            LOGGER.warning("Could not parse certificate expiry, defaulting to 30 minutes: " + e.getMessage());
            return Instant.now().plusSeconds(1800);
        }
    }

    /**
     * Extracts the full CA chain from the Vault PKI response's {@code ca_chain} JSON array.
     *
     * <p>When Vault is an intermediate CA the array contains the intermediate certificate followed
     * by all parent CAs up to the root.  Each entry is a PEM string; they are concatenated with
     * a newline so the result can be used directly as a {@code -CAfile} bundle.</p>
     *
     * <p>Falls back to {@code issuingCaPem} if {@code ca_chain} is absent or empty (root CA
     * setup or older Vault versions).</p>
     */
    static String extractCaChain(LogicalResponse response, String issuingCaPem) {
        try {
            JsonObject dataObject = response.getDataObject();
            if (dataObject == null) {
                return issuingCaPem;
            }
            JsonValue caChainValue = dataObject.get("ca_chain");
            if (caChainValue == null || caChainValue.isNull()) {
                return issuingCaPem;
            }
            JsonArray caChainArray = caChainValue.asArray();
            if (caChainArray == null || caChainArray.values().isEmpty()) {
                return issuingCaPem;
            }
            StringBuilder sb = new StringBuilder();
            for (JsonValue v : caChainArray.values()) {
                String pem = v.asString();
                if (isNotBlank(pem)) {
                    sb.append(pem.trim()).append('\n');
                }
            }
            String chain = sb.toString().trim();
            return isNotBlank(chain) ? chain : issuingCaPem;
        } catch (Exception e) {
            LOGGER.warning("Could not read ca_chain from Vault response, falling back to issuing_ca: "
                + e.getMessage());
            return issuingCaPem;
        }
    }

    /**
     * Fails with Vault's own error messages when the issue request was rejected (HTTP 4xx/5xx),
     * e.g. an unknown role or a common name the role does not allow.
     */
    static void checkResponseStatus(LogicalResponse response, String path) {
        RestResponse restResponse = response.getRestResponse();
        if (restResponse == null || restResponse.getStatus() < 400) {
            return;
        }
        String detail = "";
        try {
            byte[] body = restResponse.getBody();
            if (body != null && body.length > 0) {
                JsonValue errors = Json.parse(new String(body, StandardCharsets.UTF_8))
                    .asObject().get("errors");
                if (errors != null && errors.isArray()) {
                    List<String> messages = new ArrayList<>();
                    for (JsonValue v : errors.asArray().values()) {
                        messages.add(v.asString());
                    }
                    detail = ": " + String.join("; ", messages);
                }
            }
        } catch (Exception ignored) {
            // body is not the usual {"errors": [...]} JSON - report the status code only
        }
        throw new VaultPluginException(String.format(
            "Vault rejected the request to '%s' (HTTP %d)%s", path, restResponse.getStatus(), detail));
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
    /**
     * Builds a PKCS12 {@link KeyStore} from PEM-encoded certificate data returned by the Vault
     * PKI engine.
     *
     * <p>{@code caChainPem} may contain a single certificate (root CA setup) or multiple
     * concatenated PEM blocks (intermediate CA setup: intermediate + root).  All CA certificates
     * are included in the PKCS12 certificate chain so TLS clients can verify the full path to the
     * root without needing to install the root CA separately.</p>
     */
    static KeyStore buildKeyStore(String certPem, String privateKeyPem, String caChainPem,
        char[] password)
        throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        X509Certificate cert = (X509Certificate) cf.generateCertificate(
            new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8)));

        // Parse all CA certificates from the chain PEM (handles both single and multi-cert bundles)
        Collection<? extends Certificate> chainCerts = cf.generateCertificates(
            new ByteArrayInputStream(caChainPem.getBytes(StandardCharsets.UTF_8)));

        List<Certificate> certChain = new ArrayList<>();
        certChain.add(cert);
        certChain.addAll(chainCerts);

        PrivateKey privateKey = parsePrivateKey(privateKeyPem);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password);
        ks.setKeyEntry("vault-pki", privateKey, password, certChain.toArray(new Certificate[0]));
        return ks;
    }

    /**
     * Parses a PEM-encoded private key.
     *
     * <ul>
     *   <li>{@code -----BEGIN PRIVATE KEY-----} – PKCS#8, works for RSA and EC.</li>
     *   <li>{@code -----BEGIN RSA PRIVATE KEY-----} – PKCS#1 RSA, converted via a minimal
     *       DER wrapper.</li>
     *   <li>{@code -----BEGIN EC PRIVATE KEY-----} (SEC1) – <strong>not supported</strong>.  It is
     *       not expected because issuance requests {@code private_key_format=pkcs8} (see
     *       {@link #buildIssueParams}); a {@link VaultPluginException} reports it if a Vault
     *       version ignores that parameter.</li>
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
            // Only reached if Vault ignored private_key_format=pkcs8; SEC1 would need an ASN.1
            // conversion to PKCS#8, which is not implemented.
            throw new VaultPluginException(
                "Vault returned an EC private key in SEC1 format (BEGIN EC PRIVATE KEY) although "
                    + "PKCS#8 was requested (private_key_format=pkcs8). Use a Vault version that "
                    + "supports private_key_format, or configure the PKI role to use RSA keys. "
                    + "See https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-certificate-and-key");
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
        /** Certificate, private key and CA certificates of this issuance. */
        final VaultPKICertificateBundle bundle;
        /** Vault lease ID (only set when the PKI role uses {@code generate_lease=true}). */
        final Secret leaseId;
        /**
         * Time after which the cache should be considered stale, see {@link #computeRenewAfter}.
         * {@link #getOrIssue()} re-issues once this point is reached.
         */
        final Instant renewAfter;

        IssuedCertificate(VaultPKICertificateBundle bundle, Secret leaseId, Instant renewAfter) {
            this.bundle = bundle;
            this.leaseId = leaseId;
            this.renewAfter = renewAfter;
        }
    }

    // ---- Jenkins descriptor ----------------------------------------------------

    @Symbol("vaultPKICert")
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

        @POST
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
                String issuePath = buildIssuePath(
                    defaultIfBlank(Util.fixEmptyAndTrim(pkiMount), DEFAULT_PKI_MOUNT),
                    Util.fixEmptyAndTrim(pkiRole));

                Map<String, Object> params = buildIssueParams(commonName, ttl, altNames, ipSans);

                LogicalResponse response = writeVaultSecret(issuePath, params,
                    Util.fixEmptyAndTrim(namespace), context);
                checkResponseStatus(response, issuePath);
                Map<String, String> data = response.getData();

                if (data == null || data.get("certificate") == null) {
                    return FormValidation.error(
                        "Vault returned a response but 'certificate' field was missing");
                }
                return FormValidation.ok("Successfully issued certificate from Vault PKI");
            } catch (Exception e) {
                return FormValidation.error("FAILED to issue PKI certificate: " + e.getMessage());
            }
        }
    }
}
