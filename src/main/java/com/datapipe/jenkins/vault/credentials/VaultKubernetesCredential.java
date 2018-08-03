package com.datapipe.jenkins.vault.credentials;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

import org.kohsuke.stapler.DataBoundConstructor;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.datapipe.jenkins.vault.exception.VaultPluginException;

import hudson.Extension;
import hudson.util.Secret;

import java.nio.file.*;

public class VaultKubernetesCredential extends BaseStandardCredentials implements VaultCredential {
    private final @Nonnull String role;

    @DataBoundConstructor
    public VaultKubernetesCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id, @CheckForNull String description, @Nonnull String role) {
        super(scope, id, description);
        this.role = role;
    }

    public String getRole() {
        return role;
    }

    @Override
    public Vault authorizeWithVault(Vault vault, VaultConfig config) {
        String token = null;

	// TODO: add error handle here
	String jwt = new String(Files.readAllBytes(Paths.get("/var/run/secrets/kubernetes.io/serviceaccount/token")));

        try {
            token = vault.auth().loginByKubernetes(role, jwt).getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault", e);
        }
        return new Vault(config.token(token));
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override public String getDisplayName() {
            return "Vault Kubernetes Credential";
        }

    }
}
