package com.datapipe.jenkins.vault.credentials.common;

import com.amazonaws.auth.AWSCredentials;
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
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;

import com.amazonaws.auth.AWSCredentials;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static org.apache.commons.lang.StringUtils.defaultIfBlank;

public class VaultAwsCredentialBinding extends
        MultiBinding<VaultAwsCredential> {

    public static final String DEFAULT_ACCESS_KEY_ID_VARIABLE = "AWS_ACCESS_KEY_ID";
    public static final String DEFAULT_SECRET_ACCESS_KEY_VARIABLE = "AWS_SECRET_ACCESS_KEY";
    private String accessKeyVariable;
    private String secretKeyVariable;

    @DataBoundConstructor
    public VaultAwsCredentialBinding(@Nullable String accessKeyVariable,
            @Nullable String secretKeyVariable,
            String credentialsId) {
        super(credentialsId);
        this.accessKeyVariable = defaultIfBlank(accessKeyVariable, DEFAULT_ACCESS_KEY_ID_VARIABLE);
        this.secretKeyVariable = defaultIfBlank(secretKeyVariable, DEFAULT_SECRET_ACCESS_KEY_VARIABLE);
    }

    @Override
    protected Class<VaultAwsCredential> type() {
        return VaultAwsCredential.class;
    }

    @Override
    public MultiEnvironment bind(@Nonnull Run<?, ?> build, FilePath workspace, Launcher launcher,
            TaskListener listener)
            throws IOException, InterruptedException {
        AWSCredentials credentials = this.getCredentials(build).getCredentials();
        Map<String, String> map = new HashMap<String, String>();
        map.put(this.accessKeyVariable, credentials.getAWSAccessKeyId());
        map.put(this.secretKeyVariable, credentials.getAWSSecretKey());
        return new MultiEnvironment(map);
    }

    public String getaccessKeyVariable() {
        return accessKeyVariable;
    }

    public String getsecretKeyVariable() {
        return secretKeyVariable;
    }

    @Override
    public Set<String> variables() {
        Set<String> variables = new HashSet<String>();
        variables.add(this.accessKeyVariable);
        variables.add(this.secretKeyVariable);
        return variables;
    }

    @Extension
    public static class DescriptorImpl extends BindingDescriptor<VaultAwsCredential> {

        @Override
        protected Class<VaultAwsCredential> type() {
            return VaultAwsCredential.class;
        }

        @Override
        public String getDisplayName() {
            return "Vault AWS Credentials";
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }
}
