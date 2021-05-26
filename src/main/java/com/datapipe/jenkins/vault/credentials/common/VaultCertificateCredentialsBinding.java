package com.datapipe.jenkins.vault.credentials.common;

import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.ListBoxModel;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.UnbindableDir;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static org.apache.commons.lang.StringUtils.defaultIfBlank;

public class VaultCertificateCredentialsBinding extends
    MultiBinding<VaultCertificateCredentials> {

    public static final String DEFAULT_KEYSTORE_VARIABLE = "KEYSTORE";
    public static final String DEFAULT_PASSWORD_VARIABLE = "PASSWORD";
    private String keyStoreVariable;
    private String passwordVariable;

    @DataBoundConstructor
    public VaultCertificateCredentialsBinding(@Nullable String keyStoreVariable,
        @Nullable String passwordVariable,
        String credentialsId) {
        super(credentialsId);
        this.keyStoreVariable = defaultIfBlank(keyStoreVariable, DEFAULT_KEYSTORE_VARIABLE);
        this.passwordVariable = defaultIfBlank(passwordVariable, DEFAULT_PASSWORD_VARIABLE);
    }

    @Override
    protected Class<VaultCertificateCredentials> type() {
        return VaultCertificateCredentials.class;
    }

    @Override
    public MultiEnvironment bind(@Nonnull Run<?, ?> build, FilePath workspace, Launcher launcher,
        TaskListener listener)
        throws IOException, InterruptedException {
        VaultCertificateCredentials credentials = this.getCredentials(build);
        UnbindableDir keyStoreDir = UnbindableDir.create(workspace);

        FilePath keyStoreFile = keyStoreDir.getDirPath().child(String.format("keystore-%s", this.keyStoreVariable));
        credentials.write(keyStoreFile);

        Map<String, String> map = new HashMap<String, String>();
        map.put(this.keyStoreVariable, keyStoreFile.getRemote());
        map.put(this.passwordVariable, credentials.getPassword().getPlainText());
        return new MultiEnvironment(map);
    }

    public String getKeyStoreVariable() {
        return keyStoreVariable;
    }

    public String getPasswordVariable() {
        return passwordVariable;
    }

    @Override
    public Set<String> variables() {
        Set<String> variables = new HashSet<String>();
        variables.add(this.keyStoreVariable);
        variables.add(this.passwordVariable);
        return variables;
    }

    @Extension
    public static class DescriptorImpl extends BindingDescriptor<VaultCertificateCredentials> {

        @Override
        protected Class<VaultCertificateCredentials> type() {
            return VaultCertificateCredentials.class;
        }

        @Override
        public String getDisplayName() {
            return "Vault KeyStore-Password Credentials";
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }
}
