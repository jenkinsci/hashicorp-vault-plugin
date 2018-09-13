package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import com.google.common.annotations.VisibleForTesting;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class VaultTokenCredentialBinding extends MultiBinding<AbstractVaultTokenCredential> {

    private final static String DEFAULT_VAULT_ADDR_VARIABLE_NAME = "VAULT_ADDR";
    private final static String DEFAULT_VAULT_TOKEN_VARIABLE_NAME = "VAULT_TOKEN";

    @NonNull
    private final String addrVariable;
    private final String tokenVariable;
    private final String vaultAddr;

    /**
     *
     * @param addrVariable if {@code null}, {@value DEFAULT_VAULT_ADDR_VARIABLE_NAME} will be used.
     * @param tokenVariable if {@code null}, {@value DEFAULT_VAULT_TOKEN_VARIABLE_NAME} will be used.
     * @param credentialsId credential identifier
     * @param vaultAddr vault address
     */
    @DataBoundConstructor
    public VaultTokenCredentialBinding(@Nullable String addrVariable, @Nullable String tokenVariable, String credentialsId, String vaultAddr) {
        super(credentialsId);
        this.vaultAddr = vaultAddr;
        this.addrVariable = StringUtils.defaultIfBlank(addrVariable, DEFAULT_VAULT_ADDR_VARIABLE_NAME);
        this.tokenVariable = StringUtils.defaultIfBlank(tokenVariable, DEFAULT_VAULT_TOKEN_VARIABLE_NAME);
    }

    @NonNull
    public String getAddrVariable() {
        return addrVariable;
    }

    @NonNull
    public String getTokenVariable() {
        return tokenVariable;
    }

    @NonNull
    public String getVaultAddr() {
        return vaultAddr;
    }

    @Override
    protected Class<AbstractVaultTokenCredential> type() {
        return AbstractVaultTokenCredential.class;
    }

    @Override
    public MultiEnvironment bind(@Nonnull Run<?, ?> build, FilePath workspace, Launcher launcher, TaskListener listener) throws IOException, InterruptedException {
        AbstractVaultTokenCredential credentials = getCredentials(build);
        Map<String,String> m = new HashMap<String,String>();
        m.put(addrVariable, vaultAddr);
        m.put(tokenVariable, getToken(credentials));

        return new MultiEnvironment(m);
    }

    private String getToken(AbstractVaultTokenCredential credentials) {
        try {
            VaultConfig config = new VaultConfig().address(vaultAddr).build();
            return credentials.getToken(new Vault(config));
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault", e);
        }
    }

    @Override
    public Set<String> variables() {
        return new HashSet<String>(Arrays.asList(addrVariable, tokenVariable));
    }

    @Extension
    public static class DescriptorImpl extends BindingDescriptor<AbstractVaultTokenCredential> {

        @Override protected Class<AbstractVaultTokenCredential> type() {
            return AbstractVaultTokenCredential.class;
        }

        @Override public String getDisplayName() {
            return "HashiCorp Vault: Address and Token";
        }
    }

}

