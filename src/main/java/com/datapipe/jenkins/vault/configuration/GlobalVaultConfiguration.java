package com.datapipe.jenkins.vault.configuration;

import com.datapipe.jenkins.vault.configuration.VaultConfiguration.DescriptorImpl;
import hudson.Extension;
import hudson.model.Item;
import jenkins.model.GlobalConfiguration;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.Nonnull;

@Extension
public class GlobalVaultConfiguration extends GlobalConfiguration {
    private VaultConfiguration configuration;

    @Nonnull
    public static GlobalVaultConfiguration get() {
        GlobalVaultConfiguration instance = GlobalConfiguration.all().get(GlobalVaultConfiguration.class);
        if (instance == null) {
            throw new IllegalStateException();
        }
        return instance;
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

        @Nonnull
        @Override
        public VaultConfiguration forJob(@Nonnull Item job) {
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
