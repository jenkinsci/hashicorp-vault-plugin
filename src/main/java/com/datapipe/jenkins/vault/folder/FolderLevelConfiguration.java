package com.datapipe.jenkins.vault.folder;

import com.bettercloud.vault.Vault;
import com.cloudbees.hudson.plugins.folder.properties.FolderCredentialsProvider;
import com.cloudbees.plugins.credentials.common.AbstractIdCredentialsListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.datapipe.jenkins.vault.VaultBuildWrapper;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import hudson.model.Job;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.AbstractFolderProperty;
import com.cloudbees.hudson.plugins.folder.AbstractFolderPropertyDescriptor;

import hudson.Extension;
import net.sf.json.JSONObject;

public class FolderLevelConfiguration extends AbstractFolderProperty<AbstractFolder<?>> {
    private String vaultUrl;
    private String appRoleCredentialId;

    @DataBoundConstructor
    public FolderLevelConfiguration() {
        System.out.println("constructor of discrabable");
    }

    public String getVaultUrl() {
        return vaultUrl;
    }

    @DataBoundSetter
    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = vaultUrl;
    }

    public String getAppRoleCredentialId() {
        return appRoleCredentialId;
    }

    @DataBoundSetter
    public void setAppRoleCredentialId(String appRoleCredentialId) {
        this.appRoleCredentialId = appRoleCredentialId;
    }

    @Extension
    public static class DescriptorImpl extends AbstractFolderPropertyDescriptor {

        private FolderLevelConfiguration folderLevelConfiguration;

        public DescriptorImpl() {
            super();
            load();
        }

        @Override
        public String getDisplayName() {
            return "Vault Folder Credentials";
        }

        @Override
        public AbstractFolderProperty<?> newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            FolderLevelConfiguration prop = (FolderLevelConfiguration) super.newInstance(req, formData);
            this.folderLevelConfiguration = prop;
            save();
            return prop;
        }

        public ListBoxModel doFillAppRoleCredentialIdItems(@AncestorInPath Job context, @QueryParameter String source, @QueryParameter String value){
            if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                return new ListBoxModel();
            }

            AbstractIdCredentialsListBoxModel model = new StandardListBoxModel().includeEmptyValue().includeAs(ACL.SYSTEM, context, VaultTokenCredential.class);
            return model;
        }

        public FolderLevelConfiguration getFolderLevelConfiguration() {
            return folderLevelConfiguration;
        }
    }
}
