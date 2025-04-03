package com.datapipe.jenkins.vault.credentials.common;

import edu.umd.cs.findbugs.annotations.NonNull;
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
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static org.apache.commons.lang.StringUtils.defaultIfBlank;

public class VaultUsernamePasswordCredentialBinding extends
    MultiBinding<VaultUsernamePasswordCredential> {

    public static final String DEFAULT_USERNAME_VARIABLE = "USERNAME";
    public static final String DEFAULT_PASSWORD_VARIABLE = "PASSWORD";
    private String usernameVariable;
    private String passwordVariable;

    @DataBoundConstructor
    public VaultUsernamePasswordCredentialBinding(@Nullable String usernameVariable,
        @Nullable String passwordVariable,
        String credentialsId) {
        super(credentialsId);
        this.usernameVariable = defaultIfBlank(usernameVariable, DEFAULT_USERNAME_VARIABLE);
        this.passwordVariable = defaultIfBlank(passwordVariable, DEFAULT_PASSWORD_VARIABLE);
    }

    @Override
    protected Class<VaultUsernamePasswordCredential> type() {
        return VaultUsernamePasswordCredential.class;
    }

    @Override
    public MultiEnvironment bind(@NonNull Run<?, ?> build, FilePath workspace, Launcher launcher,
        TaskListener listener)
        throws IOException, InterruptedException {
        VaultUsernamePasswordCredential credentials = this.getCredentials(build);
        Map<String, String> map = new HashMap<>();
        map.put(this.usernameVariable, credentials.getUsername());
        map.put(this.passwordVariable, credentials.getPassword().getPlainText());
        return new MultiEnvironment(map);
    }

    public String getUsernameVariable() {
        return usernameVariable;
    }

    public String getPasswordVariable() {
        return passwordVariable;
    }

    @Override
    public Set<String> variables() {
        Set<String> variables = new HashSet<>();
        variables.add(this.usernameVariable);
        variables.add(this.passwordVariable);
        return variables;
    }

    @Extension
    public static class DescriptorImpl extends BindingDescriptor<VaultUsernamePasswordCredential> {

        @Override
        protected Class<VaultUsernamePasswordCredential> type() {
            return VaultUsernamePasswordCredential.class;
        }

        @Override
        public String getDisplayName() {
            return "Vault Username-Password Credentials";
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }
}
