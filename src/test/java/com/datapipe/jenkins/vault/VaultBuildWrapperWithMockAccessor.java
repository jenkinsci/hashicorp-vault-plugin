package com.datapipe.jenkins.vault;

import com.datapipe.jenkins.vault.model.VaultSecret;
import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.tasks.BuildWrapper;
import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.CheckForNull;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/*
This class is only used for testing the Jenkinsfile - we can not inject our
 MockAccessor there and therefore need to mimic it's behaviour here.
 */
public class VaultBuildWrapperWithMockAccessor extends VaultBuildWrapper {

    @DataBoundConstructor
    public VaultBuildWrapperWithMockAccessor(@CheckForNull List<VaultSecret> vaultSecrets) {
        super(vaultSecrets);
        setVaultAccessor(new VaultAccessor() {
            @Override
            public void init(String url) {
                if (!url.equals("http://jenkinsfile-vault-url.com")) {
                    throw new AssertionError("URL " + url + " does not match expected value of " + "http://jenkinsfile-vault-url.com");
                }
            }

            @Override
            public void auth(String roleId, Secret secretId) {
                if (!roleId.equals("role-id-global-2") || !secretId.getPlainText().equals("secret-id-global-2")) {
                    throw new AssertionError("role-id " + roleId + " or secret-id " + secretId + " do not match expected: -global-2");
                }

            }

            @Override
            public Map<String, String> read(String path) {
                if (!path.equals("secret/path1")) {
                    throw new AssertionError("path " + path + " does not match expected: secret/path1");
                }
                Map<String, String> returnValue = new HashMap<>();
                returnValue.put("key1", "some-secret");
                return returnValue;
            }
        });
    }
        @Extension
        public static final class DescriptorImpl extends Descriptor<BuildWrapper> {
            public DescriptorImpl() {
                super(VaultBuildWrapperWithMockAccessor.class);
                load();
            }

            public boolean isApplicable(AbstractProject<?, ?> item) {
                return true;
            }

            @Override
            public String getDisplayName() {
                return "Vault Mock Plugin";
            }
        }
}
