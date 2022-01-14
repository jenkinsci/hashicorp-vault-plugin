package com.datapipe.jenkins.vault.configuration;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.AbstractFolderProperty;
import com.cloudbees.hudson.plugins.folder.AbstractFolderPropertyDescriptor;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import org.kohsuke.stapler.DataBoundConstructor;

public class FolderVaultConfiguration extends AbstractFolderProperty<AbstractFolder<?>> {

    private final VaultConfiguration configuration;

    public FolderVaultConfiguration() {
        this.configuration = null;
    }

    @DataBoundConstructor
    public FolderVaultConfiguration(VaultConfiguration configuration) {
        this.configuration = configuration;
    }

    public VaultConfiguration getConfiguration() {
        return configuration;
    }

    @Extension
    public static class DescriptorImpl extends AbstractFolderPropertyDescriptor {

    }

    @Extension(ordinal = 100)
    public static class ForJob extends VaultConfigResolver {

        @NonNull
        @Override
        public VaultConfiguration forJob(@NonNull Item job) {
            VaultConfiguration resultingConfig = null;
            for (ItemGroup g = job.getParent(); g instanceof AbstractFolder;
                g = ((AbstractFolder) g).getParent()) {
                FolderVaultConfiguration folderProperty = ((AbstractFolder<?>) g).getProperties()
                    .get(FolderVaultConfiguration.class);
                if (folderProperty == null) {
                    continue;
                }
                if (resultingConfig != null) {
                    resultingConfig = resultingConfig
                        .mergeWithParent(folderProperty.getConfiguration());
                } else {
                    resultingConfig = folderProperty.getConfiguration();
                }
            }

            return resultingConfig;
        }
    }
}
