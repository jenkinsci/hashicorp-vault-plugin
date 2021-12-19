package com.datapipe.jenkins.vault.configuration;

import com.datapipe.jenkins.vault.configuration.VaultConfiguration.DescriptorImpl;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.Item;
import hudson.model.ItemGroup;
import jenkins.model.GlobalConfiguration;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

@Extension
@Symbol("hashicorpVault")
public class GlobalVaultConfiguration extends GlobalConfiguration {

    private VaultConfiguration configuration;

    public static GlobalVaultConfiguration get() {
        return ExtensionList.lookupSingleton(GlobalVaultConfiguration.class);
    }

    public GlobalVaultConfiguration() {
        load();
    }

    public VaultConfiguration getConfiguration() {
        return configuration;
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
        req.bindJSON(this, json);
        return true;
    }

    @DataBoundSetter
    public void setConfiguration(VaultConfiguration configuration) {
        this.configuration = configuration;
        if (this.configuration != null && this.configuration.getEngineVersion() == null) {
            this.configuration.setEngineVersion(DescriptorImpl.DEFAULT_ENGINE_VERSION);
        }
        save();
    }

    @Extension(ordinal = 0)
    public static class ForJob extends VaultConfigResolver {

        @NonNull
        @Override
        public VaultConfiguration forJob(@NonNull Item job) {
            return getVaultConfig(job.getParent());
        }

        @Override
        public VaultConfiguration getVaultConfig(@NonNull ItemGroup<? extends Item> itemGroup) {
            return GlobalVaultConfiguration.get().getConfiguration();
        }
    }

    protected Object readResolve() {
        if (configuration != null && configuration.getEngineVersion() == null) {
            configuration.setEngineVersion(DescriptorImpl.DEFAULT_ENGINE_VERSION);
        }
        return this;
    }

}
