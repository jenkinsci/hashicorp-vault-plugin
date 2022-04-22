package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import hudson.model.ItemGroup;
import java.util.Map;
import org.kohsuke.stapler.DataBoundSetter;

import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecretKey;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecret;

/**
 * Base Vault credentials that contain a {@code path}, {@code prefixPath}, {@code namespace},
 * and {@code engineVersion}.
 */
public abstract class AbstractVaultBaseStandardCredentials extends BaseStandardCredentials {

    private String path;
    private String prefixPath;
    private String namespace;
    private Integer engineVersion;

    AbstractVaultBaseStandardCredentials(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }

    @NonNull
    public String getPrefixPath() {
        return prefixPath;
    }

    @DataBoundSetter
    public void setPrefixPath(String prefixPath) {
        this.prefixPath = Util.fixEmptyAndTrim(prefixPath);
    }

    @NonNull
    public String getPath() {
        return path;
    }

    @DataBoundSetter
    public void setPath(String path) {
        this.path = path;
    }

    @CheckForNull
    public String getNamespace() {
        return namespace;
    }

    @DataBoundSetter
    public void setNamespace(String namespace) {
        this.namespace = Util.fixEmptyAndTrim(namespace);
    }

    @CheckForNull
    public Integer getEngineVersion() {
        return engineVersion;
    }

    @DataBoundSetter
    public void setEngineVersion(Integer engineVersion) {
        this.engineVersion = engineVersion;
    }

    /**
     * Look up secret key value.
     * @param key secret key name
     * @return vault secret value
     */
    @NonNull
    protected String getVaultSecretKeyValue(String key) {
        String s = getVaultSecretKey(this.path, key, this.prefixPath, this.namespace, this.engineVersion);
        if (s == null) {
            throw new VaultPluginException("Fetching from Vault failed for key '" + key + "'");
        }
        return s;
    }

    /**
     * Look up the secret key:value map.
     * @return vault secret value
     */
    @NonNull
    protected Map<String, String> getVaultSecretValue() {
        Map<String, String> s = getVaultSecret(this.path, this.prefixPath, this.namespace, this.engineVersion);
        if (s == null) {
            throw new VaultPluginException("Fetching from Vault failed for secret '" + this.path + "'");
        }
        return s;
    }

    /**
     * Get credential display name. Defaults to secret path.
     * @return display name
     */
    public String getDisplayName() {
        return this.path;
    }
}
