package com.datapipe.jenkins.vault;

import com.bettercloud.vault.response.LogicalResponse;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import jenkins.tasks.SimpleBuildWrapper;

import java.io.IOException;
import java.util.List;

/**
 * Created by adamtistler on 8/29/17.
 */
public class VaultDisposer extends SimpleBuildWrapper.Disposer {
    private final List<String> leaseIds;
    private final VaultAccessor vaultAccessor;

    public VaultDisposer(final VaultAccessor vaultAccessor, final List<String> leaseIds) {
        this.vaultAccessor = vaultAccessor;
        this.leaseIds = leaseIds;
    }

    @Override
    public void tearDown(final Run<?, ?> build, final FilePath workspace, final Launcher launcher, final TaskListener listener) throws IOException, InterruptedException {
        for (String leaseId : leaseIds) {
            if (leaseId != null && !leaseId.isEmpty()) {
                vaultAccessor.revoke(leaseId);
            }
        }
    }
}
