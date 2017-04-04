package com.datapipe.jenkins.vault.configuration;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.model.Job;
import jenkins.model.Jenkins;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;

import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class FolderVaultConfigurationSpec {

    private FolderVaultConfiguration completeTestConfigFolder(String identifier) {
        return new FolderVaultConfiguration(VaultConfigurationSpec.completeTestConfig(identifier));
    }

    @Test
    public void resolverShouldNotFailIfNotInFolder() {
        VaultConfigResolver folderResolver = new FolderVaultConfiguration.ForJob();
        Job job = mock(Job.class);
        when(job.getParent()).thenReturn(mock(Jenkins.class));

        VaultConfiguration result = folderResolver.forJob(job);

        assertThat(result, is(nullValue()));
    }

    @Test
    public void resolverShouldCorrectlyMerge() {
        VaultConfigResolver folderResolver = new FolderVaultConfiguration.ForJob();
        Job job = mock(Job.class);
        Folder firstParent = mock(Folder.class, Mockito.RETURNS_DEEP_STUBS);
        Folder secondParent = mock(Folder.class, Mockito.RETURNS_DEEP_STUBS);
        when(job.getParent()).thenReturn(firstParent);
        when(firstParent.getParent()).thenReturn(secondParent);
        when(firstParent.getProperties().get(FolderVaultConfiguration.class)).thenReturn(completeTestConfigFolder("firstParent"));
        when(secondParent.getProperties().get(FolderVaultConfiguration.class)).thenReturn(completeTestConfigFolder("secondParent"));

        VaultConfiguration result = folderResolver.forJob(job);

        VaultConfiguration expected = VaultConfigurationSpec.completeTestConfig("firstParent").mergeWithParent(VaultConfigurationSpec.completeTestConfig("secondParent"));

        assertThat(result.getVaultTokenCredentialId(), is(expected.getVaultTokenCredentialId()));
        assertThat(result.getVaultUrl(), is(expected.getVaultUrl()));
    }

    @Test
    public void resolverShouldHandleAbsentConfigurationOnFolders() {
        VaultConfigResolver folderResolver = new FolderVaultConfiguration.ForJob();
        Job job = mock(Job.class);
        Folder firstParent = mock(Folder.class, Mockito.RETURNS_DEEP_STUBS);
        Folder secondParent = mock(Folder.class, Mockito.RETURNS_DEEP_STUBS);
        when(job.getParent()).thenReturn(firstParent);
        when(firstParent.getParent()).thenReturn(secondParent);
        when(firstParent.getProperties().get(FolderVaultConfiguration.class)).thenReturn(completeTestConfigFolder("firstParent"));
        when(secondParent.getProperties().get(FolderVaultConfiguration.class)).thenReturn(null);

        VaultConfiguration result = folderResolver.forJob(job);

        VaultConfiguration expected = VaultConfigurationSpec.completeTestConfig("firstParent").mergeWithParent(null);

        assertThat(result.getVaultTokenCredentialId(), is(expected.getVaultTokenCredentialId()));
        assertThat(result.getVaultUrl(), is(expected.getVaultUrl()));
    }
}