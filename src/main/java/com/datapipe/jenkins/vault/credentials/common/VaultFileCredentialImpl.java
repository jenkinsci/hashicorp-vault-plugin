package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Map;
import java.util.UUID;
import org.json.simple.JSONValue;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;


import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecret;


public class VaultFileCredentialImpl extends AbstractVaultBaseStandardCredentials implements VaultFileCredential {

    public static final String DEFAULT_VAULT_KEY = "secret";

    private static final long serialVersionUID = 1L;

    private String fileName;

    @NonNull
    public String getFileName() {
        return fileName;
    }

    @DataBoundSetter
    public void setFilePath(String fileName) {
        this.fileName = fileName;
    }

    @DataBoundConstructor
    public VaultFileCredentialImpl(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
        this.fileName = UUID.randomUUID().toString();
    }


    @NonNull
    @Override
    public InputStream getContent() {
        Map<String, String> s = getVaultSecretValue();
        return new ByteArrayInputStream(JSONValue.toJSONString(s).getBytes());
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault Secret File Credential";
        }

        public FormValidation doTestConnection(
            @QueryParameter("path") String path,
            @QueryParameter("prefixPath") String prefixPath,
            @QueryParameter("namespace") String namespace,
            @QueryParameter("engineVersion") Integer engineVersion) {

            try {
                getVaultSecret(path, prefixPath, namespace, engineVersion);
            } catch (Exception e) {
                return FormValidation.error("FAILED to retrieve Vault secret: \n" + e);
            }

            return FormValidation
                .ok("Successfully retrieved secret " + path);
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }

    }

}
