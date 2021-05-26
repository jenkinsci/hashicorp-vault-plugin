package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.FilePath;
import hudson.Util;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecret;
import static org.apache.commons.lang.StringUtils.defaultIfBlank;

@SuppressWarnings("ALL")
public class VaultCertificateCredentialsImpl extends AbstractVaultBaseStandardCredentials implements
    VaultCertificateCredentials {

    private static final Logger LOGGER = Logger.getLogger(VaultCertificateCredentialsImpl.class.getName());

    public static final String DEFAULT_KEYSTORE_KEY = "keystore";
    public static final String DEFAULT_PASSWORD_KEY = "password";

    private static final long serialVersionUID = 1L;

    private String keyStoreKey;
    private String passwordKey;

    @DataBoundConstructor
    public VaultCertificateCredentialsImpl(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
    }

    @NonNull
    public String getKeyStoreKeyKey() {
        return keyStoreKey;
    }

    @DataBoundSetter
    public void setKeyStoreKey(String keyStoreKey) {
        this.keyStoreKey = defaultIfBlank(keyStoreKey, DEFAULT_KEYSTORE_KEY);
    }

    @NonNull
    public String getPasswordKey() {
        return passwordKey;
    }

    @DataBoundSetter
    public void setPasswordKey(String passwordKey) {
        this.passwordKey = defaultIfBlank(passwordKey, DEFAULT_PASSWORD_KEY);
    }

    @NonNull
    @Override
    public KeyStore getKeyStore() {
        String secretKey = defaultIfBlank(keyStoreKey, DEFAULT_KEYSTORE_KEY);
        String base64KeyStore = getVaultSecretKeyValue(secretKey);

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            throw new IllegalStateException("PKCS12 is a keystore type per the JLS spec", e);
        }
        try {
            keyStore.load(new ByteArrayInputStream(Base64.getDecoder().decode(unwrap(base64KeyStore))), toCharArray(getPassword()));
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            LogRecord lr = new LogRecord(Level.WARNING, "Credentials ID {0}: Could not load keystore from Vault");
            lr.setParameters(new Object[] { getId() });
            lr.setThrown(e);
            LOGGER.log(lr);
        }
        return keyStore;
    }

    @NonNull
    @Override
    public Secret getPassword() {
        String secretKey = defaultIfBlank(passwordKey, DEFAULT_PASSWORD_KEY);
        String secret = getVaultSecretKeyValue(secretKey);
        return Secret.fromString(secret);
    }

    @Override
    public void write(FilePath keyStoreFile) throws IOException {
        try {
            getKeyStore().store(keyStoreFile.write(), toCharArray(getPassword()));
        } catch (KeyStoreException | CertificateException | InterruptedException | NoSuchAlgorithmException e) {
            LogRecord lr = new LogRecord(Level.WARNING, "Credentials ID {0}: Could not write keystore to file");
            lr.setParameters(new Object[] { getId() });
            lr.setThrown(e);
            LOGGER.log(lr);
        }
    }

    /**
     * Helper to convert a {@link Secret} password into a {@code char[]}
     *
     * @param password the password.
     * @return a {@code char[]} containing the password or {@code null}
     */
    @CheckForNull
    private static char[] toCharArray(@NonNull Secret password) {
        String plainText = Util.fixEmpty(password.getPlainText());
        return plainText == null ? null : plainText.toCharArray();
    }

    @CheckForNull
    private static String unwrap(@NonNull String wrapped) {
        return wrapped == null ? null : Pattern.compile("\\r?\\n").matcher(wrapped).replaceAll("");
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault Certificate Credential";
        }

        public FormValidation doTestConnection(
            @QueryParameter("path") String path,
            @QueryParameter("keyStoreKey") String keyStoreKey,
            @QueryParameter("passwordKey") String passwordKey,
            @QueryParameter("prefixPath") String prefixPath,
            @QueryParameter("namespace") String namespace,
            @QueryParameter("engineVersion") Integer engineVersion) {

            try {
                getVaultSecret(path, defaultIfBlank(keyStoreKey, DEFAULT_KEYSTORE_KEY), prefixPath, namespace, engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve keyStore key: \n" + e);
            }

            try {
                getVaultSecret(path, defaultIfBlank(passwordKey, DEFAULT_PASSWORD_KEY), prefixPath, namespace, engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve password key: \n" + e);
            }

            return FormValidation
                .ok("Successfully retrieved keyStore and the password");
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }
}
