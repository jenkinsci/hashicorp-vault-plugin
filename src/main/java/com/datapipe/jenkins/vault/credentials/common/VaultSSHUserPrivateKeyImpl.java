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
import javax.annotation.Nonnull;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;

@SuppressWarnings("ALL")
public class VaultSSHUserPrivateKeyImpl extends BaseStandardCredentials implements
    VaultSSHUserPrivateKey {

    public static final String DEFAULT_USERNAME_KEY = "username";
    public static final String DEFAULT_PRIVATE_KEY_KEY = "private_key";
    public static final String DEFAULT_PASSPHRASE_KEY = "passphrase";
    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = Logger
        .getLogger(VaultSSHUserPrivateKeyImpl.class.getName());
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
        this.usernameKey = StringUtils.isEmpty(usernameKey) ? DEFAULT_USERNAME_KEY : usernameKey;
    }

    @NonNull
    public String getPrivateKeyKey() {
        return privateKeyKey;
    }

    @DataBoundSetter
    public void setPrivateKeyKey(String privateKeyKey) {
        this.privateKeyKey = StringUtils.isEmpty(privateKeyKey) ? DEFAULT_PRIVATE_KEY_KEY : privateKeyKey;
    }

    @NonNull
    public String getPassphraseKey() {
        return passphraseKey;
    }

    @DataBoundSetter
    public void setPassphraseKey(String passphraseKey) {
        this.passphraseKey = StringUtils.isEmpty(passphraseKey) ? DEFAULT_PASSPHRASE_KEY : passphraseKey;
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
        return getValue(this.usernameKey);
    }

    @NonNull
    @Override
    public String getPrivateKey() {
        return getValue(this.privateKeyKey);
    }

    @NonNull
    @Override
    public List<String> getPrivateKeys() {
        return Collections.singletonList(getPrivateKey());
    }

    @NonNull
    @Override
    public Secret getPassphrase() {
        return Secret.fromString(getValue(this.passphraseKey));
    }


    private String getValue(@Nonnull String valueKey) {
        return VaultHelper.getVaultSecret(this.getPath(), valueKey, this.getEngineVersion());
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

            String username = null;
            try {
                username = VaultHelper.getVaultSecret(path, usernameKey, engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve username key: \n" + e);
            }

            try {
                VaultHelper.getVaultSecret(path, privateKeyKey, engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve private key key: \n" + e);
            }

            try {
                VaultHelper.getVaultSecret(path, passphraseKey, engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve passphrase key: \n" + e);
            }

            return FormValidation
                .ok("Successfully retrieved username " + username + ", the private key and the passphrase");
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }
}
