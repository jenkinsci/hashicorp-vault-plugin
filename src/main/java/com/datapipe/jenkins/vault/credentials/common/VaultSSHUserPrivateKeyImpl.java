package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecret;
import static org.apache.commons.lang.StringUtils.defaultIfBlank;

@SuppressWarnings("ALL")
public class VaultSSHUserPrivateKeyImpl extends BaseStandardCredentials implements
    VaultSSHUserPrivateKey {

    private static final Logger LOGGER = Logger
        .getLogger(VaultSSHUserPrivateKeyImpl.class.getName());

    public static final String DEFAULT_USERNAME_KEY = "username";
    public static final String DEFAULT_PRIVATE_KEY_KEY = "private_key";
    public static final String DEFAULT_PASSPHRASE_KEY = "passphrase";

    private static final long serialVersionUID = 1L;

    private String path;
    private String usernameKey;
    private String privateKeyKey;
    private String passphraseKey;
    private Integer engineVersion;

    @DataBoundConstructor
    public VaultSSHUserPrivateKeyImpl(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
    }

    @NonNull
    public String getPath() {
        return path;
    }

    @DataBoundSetter
    public void setPath(String path) {
        this.path = path;
    }

    @NonNull
    public String getUsernameKey() {
        return usernameKey;
    }

    @DataBoundSetter
    public void setUsernameKey(String usernameKey) {
        this.usernameKey = defaultIfBlank(usernameKey, DEFAULT_USERNAME_KEY);
    }

    @NonNull
    public String getPrivateKeyKey() {
        return privateKeyKey;
    }

    @DataBoundSetter
    public void setPrivateKeyKey(String privateKeyKey) {
        this.privateKeyKey = defaultIfBlank(privateKeyKey, DEFAULT_PRIVATE_KEY_KEY);
    }

    @NonNull
    public String getPassphraseKey() {
        return passphraseKey;
    }

    @DataBoundSetter
    public void setPassphraseKey(String passphraseKey) {
        this.passphraseKey = defaultIfBlank(passphraseKey, DEFAULT_PASSPHRASE_KEY);
    }

    public Integer getEngineVersion() {
        return engineVersion;
    }

    @DataBoundSetter
    public void setEngineVersion(Integer engineVersion) {
        this.engineVersion = engineVersion;
    }


    @Override
    public String getDisplayName() {
        return this.path;
    }
    @NonNull
    @Override
    public String getUsername() {
        String secretKey = defaultIfBlank(usernameKey, DEFAULT_USERNAME_KEY);
        return getVaultSecret(path, secretKey, engineVersion);
    }

    @NonNull
    @Override
    public String getPrivateKey() {
        String secretKey = defaultIfBlank(privateKeyKey, DEFAULT_PRIVATE_KEY_KEY);
        return getVaultSecret(path, secretKey, engineVersion);
    }

    @NonNull
    @Override
    public List<String> getPrivateKeys() {
        return Collections.singletonList(getPrivateKey());
    }

    @NonNull
    @Override
    public Secret getPassphrase() {
        String secretKey = defaultIfBlank(passphraseKey, DEFAULT_PASSPHRASE_KEY);
        String secret = getVaultSecret(path, secretKey, engineVersion);
        return Secret.fromString(secret);
    }

    @Extension(ordinal = 1)
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault SSH Username with private key Credential";
        }

        public FormValidation doTestConnection(
            @QueryParameter("path") String path,
            @QueryParameter("usernameKey") String usernameKey,
            @QueryParameter("privateKeyKey") String privateKeyKey,
            @QueryParameter("passphraseKey") String passphraseKey,
            @QueryParameter("engineVersion") Integer engineVersion) {

            String username;
            try {
                username = getVaultSecret(path, defaultIfBlank(usernameKey, DEFAULT_USERNAME_KEY), engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve username key: \n" + e);
            }

            try {
                getVaultSecret(path, defaultIfBlank(privateKeyKey, DEFAULT_PRIVATE_KEY_KEY), engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve private key key: \n" + e);
            }

            try {
                getVaultSecret(path, defaultIfBlank(passphraseKey, DEFAULT_PASSPHRASE_KEY), engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve passphrase key: \n" + e);
            }

            return FormValidation.ok(String.format(
                "Successfully retrieved username %s, the private key and the passphrase",
                username));
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }
}
