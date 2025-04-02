package com.datapipe.jenkins.vault.credentials;

import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class VaultTokenCredentialBinding extends MultiBinding<AbstractVaultTokenCredential> {

    private final static String DEFAULT_VAULT_ADDR_VARIABLE_NAME = "VAULT_ADDR";
    private final static String DEFAULT_VAULT_TOKEN_VARIABLE_NAME = "VAULT_TOKEN";
    private final static String DEFAULT_VAULT_NAMESPACE_VARIABLE_NAME = "VAULT_NAMESPACE";

    @NonNull
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

    @Override
    public MultiEnvironment bind(@NonNull Run<?, ?> build, FilePath workspace, Launcher launcher,
        @NonNull TaskListener listener) throws IOException, InterruptedException {
        AbstractVaultTokenCredential credentials = getCredentials(build);
        Map<String, String> m = new HashMap<>();
        m.put(addrVariable, vaultAddr);
        m.put(namespaceVariable, vaultNamespace);
        String token = getToken(credentials);
        // don't add null token variable, can cause NPE in places where credential bindings impls
        // are not expecting null env var values.
        m.put(tokenVariable, StringUtils.defaultString(token));
        return new MultiEnvironment(m);
    }

    private String getToken(AbstractVaultTokenCredential credentials) {
        try {
            VaultConfig config = new VaultConfig().address(vaultAddr);
            if (StringUtils.isNotEmpty(vaultNamespace)) {
                config.nameSpace(vaultNamespace);
            }
            config.build();

            return credentials.getToken(Vault.create(config));
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault", e);
        }
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

