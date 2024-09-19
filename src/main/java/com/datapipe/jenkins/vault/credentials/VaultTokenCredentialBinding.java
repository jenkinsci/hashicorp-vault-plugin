package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Descriptor;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.CredentialNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class VaultTokenCredentialBinding extends MultiBinding<AbstractVaultTokenCredential> {

    private final static String DEFAULT_VAULT_ADDR_VARIABLE_NAME = "VAULT_ADDR";
    private final static String DEFAULT_VAULT_TOKEN_VARIABLE_NAME = "VAULT_TOKEN";
    private final static String DEFAULT_VAULT_NAMESPACE_VARIABLE_NAME = "VAULT_NAMESPACE";

    private final String credentialsId;
    private final String addrVariable;
    private final String tokenVariable;
    private final String vaultAddr;
    private String vaultNamespace = "";
    private String namespaceVariable = DEFAULT_VAULT_NAMESPACE_VARIABLE_NAME;

    /**
     * @param addrVariable if {@code null}, {@value DEFAULT_VAULT_ADDR_VARIABLE_NAME} will be used.
     * @param tokenVariable if {@code null}, {@value DEFAULT_VAULT_TOKEN_VARIABLE_NAME} will be
     * used.
     * @param credentialsId credential identifier
     * @param vaultAddr vault address
     */
    @DataBoundConstructor
    public VaultTokenCredentialBinding(@Nullable String addrVariable,
        @Nullable String tokenVariable, String credentialsId, String vaultAddr) {
        super(credentialsId);
        // The superclass field is private, so we need to store our own version
        this.credentialsId = credentialsId;
        this.vaultAddr = vaultAddr;
        this.addrVariable = StringUtils
            .defaultIfBlank(addrVariable, DEFAULT_VAULT_ADDR_VARIABLE_NAME);
        this.tokenVariable = StringUtils
            .defaultIfBlank(tokenVariable, DEFAULT_VAULT_TOKEN_VARIABLE_NAME);
    }

    @NonNull
    public String getVaultNamespace() {
        return vaultNamespace;
    }

    @DataBoundSetter
    public void setVaultNamespace(String vaultNamespace) {
        this.vaultNamespace = StringUtils.defaultIfBlank(vaultNamespace, "");
    }

    @NonNull
    public String getNamespaceVariable() {
        return namespaceVariable;
    }

    @DataBoundSetter
    public void setNamespaceVariable(String namespaceVariable) {
        this.namespaceVariable = StringUtils.defaultIfBlank(namespaceVariable, DEFAULT_VAULT_NAMESPACE_VARIABLE_NAME);
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

    private @Nonnull AbstractVaultTokenCredential getCredentials(@Nonnull Run<?,?> build,
        VaultConfiguration config) throws CredentialNotFoundException {
        // Copied and modified to pull the credentials ID from the Vault configuration
        IdCredentials cred = CredentialsProvider.findCredentialById(config.getVaultCredentialId(),
            IdCredentials.class, build);
        if (cred==null)
            throw new CredentialNotFoundException("Could not find credentials entry with ID '" +
                config.getVaultCredentialId() + "'");

        if (type().isInstance(cred)) {
            CredentialsProvider.track(build, cred);
            return type().cast(cred);
        }

        Descriptor expected = Jenkins.getActiveInstance().getDescriptor(type());
        throw new CredentialNotFoundException("Credentials '"+config.getVaultCredentialId()+"' is of type '"+
            cred.getDescriptor().getDisplayName()+"' where '"+
            (expected!=null ? expected.getDisplayName() : type().getName())+
            "' was expected");
    }

    @Override
    public MultiEnvironment bind(@NonNull Run<?, ?> build, FilePath workspace, Launcher launcher,
        @NonNull TaskListener listener) throws IOException {
        VaultConfiguration config = getVaultConfiguration(build);
        AbstractVaultTokenCredential credentials = getCredentials(build, config);
        Map<String, String> m = new HashMap<>();
        m.put(addrVariable, config.getVaultUrl());
        m.put(namespaceVariable, StringUtils.defaultString(config.getVaultNamespace()));
        String token = getToken(build, credentials, config);
        // don't add null token variable, can cause NPE in places where credential bindings impls
        // are not expecting null env var values.
        m.put(tokenVariable, StringUtils.defaultString(token));
        return new MultiEnvironment(m);
    }

    private VaultConfiguration getVaultConfiguration(Run<?, ?> build) {
        VaultConfiguration initialConfig = new VaultConfiguration();
        initialConfig.setVaultCredentialId(credentialsId);
        initialConfig.setVaultUrl(vaultAddr);
        initialConfig.setVaultNamespace(vaultNamespace);
        return VaultAccessor.pullAndMergeConfiguration(build, initialConfig);
    }

    private String getToken(Run<?, ?> build, AbstractVaultTokenCredential credentials,
        VaultConfiguration config) {
        if (StringUtils.isBlank(config.getPolicies())) {
            // Use simpler method to get token if no policies are set
            return credentials.getToken(new Vault(config.getVaultConfig()));
        }
        return credentials.authorizeWithVault(
            config.getVaultConfig(),
            VaultAccessor.generatePolicies(config.getPolicies(), build.getCharacteristicEnvVars())
        ).getToken();
    }

    @Override
    public Set<String> variables() {
        return new HashSet<>(Arrays.asList(addrVariable, namespaceVariable, tokenVariable));
    }

    @Extension
    public static class DescriptorImpl extends BindingDescriptor<AbstractVaultTokenCredential> {

        @Override
        protected Class<AbstractVaultTokenCredential> type() {
            return AbstractVaultTokenCredential.class;
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "HashiCorp Vault: Address, Namespace and Token";
        }
    }

}

