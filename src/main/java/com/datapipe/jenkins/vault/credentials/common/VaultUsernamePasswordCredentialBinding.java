package com.datapipe.jenkins.vault.credentials.common;

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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class VaultUsernamePasswordCredentialBinding extends MultiBinding<VaultUsernamePasswordCredential> {

    public static final String DEFAULT_USERNAME_VARIABLE = "USERNAME";
    public static final String DEFAULT_PASSWORD_VARIABLE = "PASSWORD";
    private String usernameVariable;
    private String passwordVariable;

    @DataBoundConstructor
    public VaultUsernamePasswordCredentialBinding(@Nullable String usernameVariable, @Nullable String passwordVariable,
                                            String credentialsId) {
        super(credentialsId);
        this.usernameVariable = StringUtils.defaultIfBlank(usernameVariable, DEFAULT_USERNAME_VARIABLE);
        this.passwordVariable = StringUtils.defaultIfBlank(passwordVariable, DEFAULT_PASSWORD_VARIABLE);
    }

    @Override
    protected Class<VaultUsernamePasswordCredential> type() {
        return VaultUsernamePasswordCredential.class;
    }

    @Override
    public MultiEnvironment bind(@Nonnull Run<?, ?> build, FilePath workspace, Launcher launcher, TaskListener listener) throws IOException, InterruptedException {
        VaultUsernamePasswordCredential credentials = this.getCredentials(build);
        Map<String, String> map = new HashMap<String, String>();
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
        Set<String> variables = new HashSet<String>();
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
            return "Hashicorp Vault Credentials";
        }
    }
}
