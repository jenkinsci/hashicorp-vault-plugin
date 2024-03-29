package com.datapipe.jenkins.vault.credentials.common;

import com.google.common.collect.ImmutableSet;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.UnbindableDir;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;

import static com.datapipe.jenkins.vault.WindowsFilePermissionHelper.fixSshKeyOnWindows;
import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static org.apache.commons.lang.StringUtils.defaultIfBlank;

public class VaultSSHUserPrivateKeyBinding extends
    MultiBinding<VaultSSHUserPrivateKey> {

    public static final String DEFAULT_USERNAME_VARIABLE = "USERNAME";
    public static final String DEFAULT_PRIVATE_KEY_VARIABLE = "PRIVATE_KEY";
    public static final String DEFAULT_PASSPHRASE_VARIABLE = "PASSPHRASE";
    private final String privateKeyVariable;
    private final String usernameVariable;
    private final String passphraseVariable;

    @DataBoundConstructor
    public VaultSSHUserPrivateKeyBinding(@Nullable String usernameVariable, @Nullable String privateKeyVariable, @Nullable String passphraseVariable, String credentialsId) {
        super(credentialsId);
        this.usernameVariable = defaultIfBlank(usernameVariable, DEFAULT_USERNAME_VARIABLE);
        this.privateKeyVariable = defaultIfBlank(privateKeyVariable, DEFAULT_PRIVATE_KEY_VARIABLE);
        this.passphraseVariable = defaultIfBlank(passphraseVariable, DEFAULT_PASSPHRASE_VARIABLE);
    }

    @Override
    protected Class<VaultSSHUserPrivateKey> type() {
        return VaultSSHUserPrivateKey.class;
    }

    @Override
    public Set<String> variables() {
        Set<String> set = new HashSet<>();
        set.add(privateKeyVariable);
        set.add(usernameVariable);
        set.add(passphraseVariable);
        return ImmutableSet.copyOf(set);
    }

    @Override
    public MultiEnvironment bind(Run<?, ?> build, FilePath workspace, Launcher launcher, TaskListener listener) throws IOException, InterruptedException {
        VaultSSHUserPrivateKey sshKey = getCredentials(build);
        UnbindableDir keyDir = UnbindableDir.create(workspace);
        FilePath keyFile = keyDir.getDirPath().child(String.format("ssh-key-%s", privateKeyVariable));

        StringBuilder contents = new StringBuilder();
        for (String key : sshKey.getPrivateKeys()) {
            contents.append(key);
        }
        keyFile.write(contents.toString(), "UTF-8");
        if (launcher.isUnix()) {
            keyFile.chmod(0400);
        } else {
            fixSshKeyOnWindows(Paths.get(keyFile.toURI()));
        }

        Map<String, String> map = new LinkedHashMap<>();
        map.put(privateKeyVariable, keyFile.getRemote());
        if (passphraseVariable != null) {
            Secret passphrase = sshKey.getPassphrase();
            if (passphrase != null) {
                map.put(passphraseVariable, passphrase.getPlainText());
            } else {
                map.put(passphraseVariable, "");
            }
        }
        if (usernameVariable != null) {
            map.put(usernameVariable, sshKey.getUsername());
        }

        return new MultiEnvironment(map, keyDir.getUnbinder());
    }

    @Extension
    public static class DescriptorImpl extends BindingDescriptor<VaultSSHUserPrivateKey> {

        @Override
        protected Class<VaultSSHUserPrivateKey> type() {
            return VaultSSHUserPrivateKey.class;
        }

        @Override
        public String getDisplayName() {
            return "Vault SSH Username with private key Credentials";
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }
    }
}
