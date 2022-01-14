package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import java.util.Map;
import java.util.logging.Logger;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecret;



public class VaultGCRLoginImpl extends AbstractVaultBaseStandardCredentials implements VaultGCRLogin {

    private final static Logger LOGGER = Logger.getLogger(VaultGCRLoginImpl.class.getName());

    @DataBoundConstructor
    public VaultGCRLoginImpl(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
    }

    @Override
    public String getDisplayName() {
        return "Vault Google Container Registry Login";
    }

    @NonNull
    @Override
    public Secret getPassword() {
        Map<String, String> s = getVaultSecretValue();
        String key = JSONObject.fromObject(s).toString();
        return Secret.fromString(key);
    }

    @NonNull
    @Override
    public String getUsername() {
        return "_json_key";
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault Google Container Registry Login";
        }

        public FormValidation doTestConnection(
            @QueryParameter("path") String path,
            @QueryParameter("prefixPath") String prefixPath,
            @QueryParameter("namespace") String namespace,
            @QueryParameter("engineVersion") Integer engineVersion) {


            String okMessage = "Successfully retrieved secret " + path;

            try {
                getVaultSecret(path, prefixPath, namespace, engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve Vault secret: \n" + e);
            }

            return FormValidation
                .ok(okMessage);
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }

    }
}
