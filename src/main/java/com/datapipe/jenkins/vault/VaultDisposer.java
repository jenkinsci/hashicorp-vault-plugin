package com.datapipe.jenkins.vault;

import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import io.github.jopenlibs.vault.VaultConfig;
import java.io.IOException;
import java.util.List;
import jenkins.tasks.SimpleBuildWrapper;

/**
 * Created by adamtistler on 8/29/17.
 */
public class VaultDisposer extends SimpleBuildWrapper.Disposer {

    private final List<String> leaseIds;
    private final VaultConfiguration vaultConfiguration;
    private final VaultCredential vaultCredential;

    public VaultDisposer(final VaultConfiguration vaultConfiguration,
        final VaultCredential vaultCredential, final List<String> leaseIds) {
        this.vaultConfiguration = vaultConfiguration;
        this.vaultCredential = vaultCredential;
        this.leaseIds = leaseIds;
    }

    @Override
    public void tearDown(final Run<?, ?> build, final FilePath workspace, final Launcher launcher,
        final TaskListener listener) throws IOException, InterruptedException {
        VaultConfig vaultConfig = new VaultConfig().address(vaultConfiguration.getVaultUrl());
        VaultAccessor vaultAccessor = new VaultAccessor(vaultConfig, vaultCredential).init();
        for (String leaseId : leaseIds) {
            if (leaseId != null && !leaseId.isEmpty()) {
                vaultAccessor.revoke(leaseId);
            }
        }
    }
}
