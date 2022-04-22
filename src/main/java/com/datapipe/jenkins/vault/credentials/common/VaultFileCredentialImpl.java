package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;


import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecret;
import static com.datapipe.jenkins.vault.credentials.common.VaultHelper.getVaultSecretKey;



public class VaultFileCredentialImpl extends AbstractVaultBaseStandardCredentials implements VaultFileCredential {

    private static final long serialVersionUID = 1L;

    private String fileName;
    private Boolean useKey;
    private String vaultKey;

    @DataBoundConstructor
    public VaultFileCredentialImpl(CredentialsScope scope, String id,
        String description) {
        super(scope, id, description);
        this.fileName = UUID.randomUUID().toString();
    }

    @NonNull
    public String getVaultKey() {
        return vaultKey;
    }

    @DataBoundSetter
    public void setVaultKey(String vaultKey) {
        this.vaultKey = vaultKey;
    }

    @NonNull
    public Boolean getUseKey() {
        return useKey;
    }

    @DataBoundSetter
    public void setUseKey(Boolean useKey) {
        this.useKey = useKey;
    }


    @NonNull
    public String getFileName() {
        return fileName;
    }

    @NonNull
    @Override
    public InputStream getContent() {
        String content;
        if (useKey != null && useKey) {
            content = getVaultSecretKeyValue(vaultKey);
        } else {
            Map<String, String> s = getVaultSecretValue();
            content = JSONObject.fromObject(s).toString();
        }

        return new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Vault Secret File Credential";
        }

        public FormValidation doTestConnection(
            @AncestorInPath ItemGroup<Item> context,
            @QueryParameter("path") String path,
            @QueryParameter("useKey") Boolean useKey,
            @QueryParameter("vaultKey") String vaultKey,
            @QueryParameter("prefixPath") String prefixPath,
            @QueryParameter("namespace") String namespace,
            @QueryParameter("engineVersion") Integer engineVersion) {


            String okMessage = "Successfully retrieved secret " + path;

            if(useKey) {
                try {
                    getVaultSecretKey(path, vaultKey, prefixPath, namespace, engineVersion);
                } catch (Exception e) {
                    return FormValidation.error("FAILED to retrieve key '" + vaultKey + "' Vault secret: \n" + e);
                }
                okMessage += " with key " + vaultKey;
            } else {
                try {
                    getVaultSecret(path, prefixPath, namespace, engineVersion);
                } catch (Exception e) {
                    return FormValidation.error("FAILED to retrieve Vault secret: \n" + e);
                }
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
