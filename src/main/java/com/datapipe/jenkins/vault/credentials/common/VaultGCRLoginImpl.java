package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import java.util.function.Supplier;
import java.util.logging.Logger;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecret;



public class VaultGCRLoginImpl extends AbstractVaultBaseStandardCredentials implements VaultGCRLogin {

    private final static Logger LOGGER = Logger.getLogger(VaultGCRLoginImpl.class.getName());

    private final Supplier<Secret> password;

    public VaultGCRLoginImpl(CredentialsScope scope, String id,
        String description, Supplier<Secret> passwordSupplier) {
        super(scope, id, description);
        password = passwordSupplier;
    }

    @DataBoundConstructor
    public VaultGCRLoginImpl(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
        password = null;
    }

    @Override
    public String getDisplayName() {
        return "Vault Google Container Registry Login";
    }

    @NonNull
    @Override
    public Secret getPassword() {
        if (password != null) {
            return password.get();
        }
        return Secret.fromString(JSONObject.fromObject(getVaultSecretValue()).toString());
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
            @AncestorInPath ItemGroup<Item> context,
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
