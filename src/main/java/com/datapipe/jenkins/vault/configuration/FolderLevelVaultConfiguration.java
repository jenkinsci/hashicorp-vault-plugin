package com.datapipe.jenkins.vault.configuration;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.AbstractFolderProperty;
import com.cloudbees.hudson.plugins.folder.AbstractFolderPropertyDescriptor;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;

public class FolderLevelVaultConfiguration extends AbstractFolderProperty<AbstractFolder<?>> {
    private final VaultConfiguration configuration;

    public FolderLevelVaultConfiguration() {
        this.configuration = null;
    }

    @DataBoundConstructor
    public FolderLevelVaultConfiguration(VaultConfiguration configuration) {
        this.configuration = configuration;
    }

    public VaultConfiguration getConfiguration() {
        return configuration;
    }

    @Extension
    public static class DescriptorImpl extends AbstractFolderPropertyDescriptor {

        @Override
        public AbstractFolderProperty<?> newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            FolderLevelVaultConfiguration config = (FolderLevelVaultConfiguration) super.newInstance(req, formData);
            return config.getConfiguration().isEmpty() ? null : config;
        }
    }

    @Extension(ordinal = 100)
    public static class ForJob extends VaultConfigResolver {
        @Nonnull
        @Override
        public VaultConfiguration forJob(@Nonnull Item job) {
            VaultConfiguration resultingConfig = null;
            List<VaultConfiguration> libraries = new ArrayList<>();
            for (ItemGroup g = job.getParent(); g instanceof AbstractFolder; g = ((AbstractFolder) g).getParent()) {
                FolderLevelVaultConfiguration folderProperty = ((AbstractFolder<?>) g).getProperties().get(FolderLevelVaultConfiguration.class);
                if (folderProperty==null){
                    continue;
                }
                if (resultingConfig != null) {
                    resultingConfig = resultingConfig.mergeWithParent(folderProperty.getConfiguration());
                } else {
                    resultingConfig = folderProperty.getConfiguration();
                }
            }

            return resultingConfig;
        }
    }
}
