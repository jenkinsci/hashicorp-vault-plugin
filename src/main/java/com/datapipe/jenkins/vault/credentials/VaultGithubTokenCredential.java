package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Auth;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import static org.apache.commons.lang.StringUtils.defaultIfBlank;

public class VaultGithubTokenCredential extends AbstractAuthenticatingVaultTokenCredential {

    // https://www.vaultproject.io/docs/auth/github.html#generate-a-github-personal-access-token
    private final @NonNull
    Secret accessToken;

    private @NonNull
    String mountPath = DescriptorImpl.defaultPath;

    @DataBoundConstructor
    public VaultGithubTokenCredential(@CheckForNull CredentialsScope scope,
        @CheckForNull String id,
        @CheckForNull String description,
        @NonNull Secret accessToken) {
        super(scope, id, description);
        this.accessToken = accessToken;
    }

    @NonNull
    public Secret getAccessToken() {
        return accessToken;
    }

    @NonNull
    public String getMountPath() {
        return mountPath;
    }

    @DataBoundSetter
    public void setMountPath(@NonNull String mountPath) {
        this.mountPath = defaultIfBlank(mountPath, DescriptorImpl.defaultPath);
    }

    @Override
    public String getToken(Auth auth) {
        try {
            return auth.loginByGithub(Secret.toString(accessToken), mountPath)
                .getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault", e);
        }
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        public static final String defaultPath = "github";

        @NonNull
        @Override
        public String getDisplayName() {
            return "Vault Github Token Credential";
        }
    }
}
