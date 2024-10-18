package com.datapipe.jenkins.vault.credentials.common;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecretKey;
import static org.apache.commons.lang.StringUtils.defaultIfBlank;

@SuppressWarnings("ALL")
public class VaultAwsCredentialImpl extends AbstractVaultBaseStandardCredentials implements
        VaultAwsCredential {

    public static final String DEFAULT_ACCESS_KEY_ID = "accessKeyID";
    public static final String DEFAULT_SECRET_ACCESS_KEY = "secretAccessKey";

    private static final long serialVersionUID = 1L;

    private String accessKey;
    private String secretKey;

    @DataBoundConstructor
    public VaultAwsCredentialImpl(CredentialsScope scope, String id,
            String description) {
        super(scope, id, description);
    }

    @NonNull
    public String getAccessKey() {
        return accessKey;
    }

    @DataBoundSetter
    public void setAccessKey(String accessKey) {
        this.accessKey = defaultIfBlank(accessKey, DEFAULT_ACCESS_KEY_ID);
    }

    @NonNull
    public String getSecretKey() {
        return secretKey;
    }

    @DataBoundSetter
    public void setSecretKey(String secretKey) {
        this.secretKey = defaultIfBlank(secretKey, DEFAULT_SECRET_ACCESS_KEY);
    }

    // @NonNull
    // @Override
    public String getAWSAccessKeyId() {
        String accessKeyId = defaultIfBlank(accessKey, DEFAULT_ACCESS_KEY_ID);
        return getVaultSecretKeyValue(accessKeyId);
    }

    // @NonNull
    // @Override
    public Secret getAWSSecretKey() {
        String secretKeyId = defaultIfBlank(secretKey, DEFAULT_SECRET_ACCESS_KEY);
        String secret = getVaultSecretKeyValue(secretKeyId);
        return Secret.fromString(secret);
    }

    @NonNull
    @Override
    public AWSCredentials getCredentials(String mfaToken) {
        return AmazonWebServicesCredentials.getCredentials(mfaToken);
    }

    @NonNull
    @Override
    public void refresh() {
        // no-op
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault AWSAccessKeyId-AWSSecretKey Credential";
        }

        public FormValidation doTestConnection(
                @AncestorInPath ItemGroup<Item> context,
                @QueryParameter("path") String path,
                @QueryParameter("accessKey") String accessKey,
                @QueryParameter("secretKey") String secretKey,
                @QueryParameter("prefixPath") String prefixPath,
                @QueryParameter("namespace") String namespace,
                @QueryParameter("engineVersion") Integer engineVersion) {

            Jenkins.get().checkPermission(Jenkins.ADMINISTER);

            String AWSAccessKeyId = null;
            try {
                AWSAccessKeyId = getVaultSecretKey(path, defaultIfBlank(accessKey, DEFAULT_ACCESS_KEY_ID),
                        prefixPath,
                        namespace, engineVersion, context);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve AWSAccessKeyId key: \n" + e);
            }

            try {
                getVaultSecretKey(path, defaultIfBlank(secretKey, DEFAULT_SECRET_ACCESS_KEY), prefixPath,
                        namespace,
                        engineVersion, context);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve AWSSecretKey key: \n" + e);
            }

            return FormValidation
                    .ok("Successfully retrieved AWSAccessKeyId " + AWSAccessKeyId + " and the AWSSecretKey");
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }
}
