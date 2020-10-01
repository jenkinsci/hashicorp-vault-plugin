package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class VaultKubernetesCredential extends AbstractVaultTokenCredential {

    private static final String SERVICE_ACCOUNT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    @NonNull
    private final String role;

    @NonNull
    private String mountPath = DescriptorImpl.defaultPath;

    @DataBoundConstructor
    public VaultKubernetesCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id,
        @CheckForNull String description, @NonNull String role) {
        super(scope, id, description);
        this.role = role;
    }

    @NonNull
    public String getMountPath() {
        return this.mountPath;
    }

    @DataBoundSetter
    public void setMountPath(@NonNull String mountPath) {
        this.mountPath = mountPath;
    }

    @NonNull
    public String getRole() {
        return this.role;
    }

    @Override
    @SuppressFBWarnings(value = "DMI_HARDCODED_ABSOLUTE_FILENAME")
    public String getToken(Vault vault) {
        String jwt;
        try (Stream<String> input =  Files.lines(Paths.get(SERVICE_ACCOUNT_TOKEN_PATH)) ) {
            jwt = input.collect(Collectors.joining());
        } catch (IOException e) {
            throw new VaultPluginException("could not get JWT from Service Account Token", e);
        }

        try {
            return vault
                .withRetries(5, 500)
                .auth()
                .loginByJwt(mountPath, role, jwt)
                .getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault: " + e.getMessage(), e);
        }
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Vault Kubernetes Credential";
        }

        public static final String defaultPath = "kubernetes";

    }
}
