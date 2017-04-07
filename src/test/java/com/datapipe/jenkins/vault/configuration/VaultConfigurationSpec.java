package com.datapipe.jenkins.vault.configuration;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class VaultConfigurationSpec {

    public static VaultConfiguration completeTestConfig(String identifier) {
        VaultConfiguration result = new VaultConfiguration();
        result.setVaultUrl("http://example.com/" + identifier);
        result.setVaultTokenCredentialId("credential" + identifier);
        return result;
    }

    public static VaultConfiguration urlOnlyConfig(String identifier) {
        VaultConfiguration result = new VaultConfiguration();
        result.setVaultUrl("http://example.com/" + identifier);
        return result;
    }

    public static VaultConfiguration credentialOnlyConfig(String identifier) {
        VaultConfiguration result = new VaultConfiguration();
        result.setVaultTokenCredentialId("credential" + identifier);
        return result;
    }

    @Test
    public void childShouldCompletlyOverwriteParent() {
        VaultConfiguration parent = completeTestConfig("parent");
        VaultConfiguration child = completeTestConfig("child");
        VaultConfiguration result = child.mergeWithParent(parent);

        assertThat(result.getVaultTokenCredentialId(), is(child.getVaultTokenCredentialId()));
        assertThat(result.getVaultUrl(), is(child.getVaultUrl()));
    }

    @Test
    public void childShouldPartlyOverwriteParent(){
        VaultConfiguration parent = completeTestConfig("parent");
        VaultConfiguration child = urlOnlyConfig("child");
        VaultConfiguration result = child.mergeWithParent(parent);

        assertThat(result.getVaultTokenCredentialId(), is(parent.getVaultTokenCredentialId()));
        assertThat(result.getVaultUrl(), is(child.getVaultUrl()));

        parent = completeTestConfig("parent");
        child = credentialOnlyConfig("child");
        result = child.mergeWithParent(parent);

        assertThat(result.getVaultTokenCredentialId(), is(child.getVaultTokenCredentialId()));
        assertThat(result.getVaultUrl(), is(parent.getVaultUrl()));
    }

    @Test
    public void emptyChildShouldBeOverriden(){
        VaultConfiguration parent = completeTestConfig("parent");
        VaultConfiguration child = new VaultConfiguration();
        VaultConfiguration result = child.mergeWithParent(parent);

        assertThat(result.getVaultTokenCredentialId(), is(parent.getVaultTokenCredentialId()));
        assertThat(result.getVaultUrl(), is(parent.getVaultUrl()));
    }

    @Test
    public void emptyParentShouldBeIgnored(){
        VaultConfiguration parent = new VaultConfiguration();
        VaultConfiguration child = completeTestConfig("child");
        VaultConfiguration result = child.mergeWithParent(parent);

        assertThat(result.getVaultTokenCredentialId(), is(child.getVaultTokenCredentialId()));
        assertThat(result.getVaultUrl(), is(child.getVaultUrl()));
    }

    @Test
    public void shouldHandleNull() {
        VaultConfiguration dummy = completeTestConfig("dummy");
        VaultConfiguration result = dummy.mergeWithParent(null);

        assertThat(result.getVaultTokenCredentialId(), is(dummy.getVaultTokenCredentialId()));
        assertThat(result.getVaultUrl(), is(dummy.getVaultUrl()));
    }

    @Test
    public void shouldNotStoreTrailingSlashesInUrl() {
        VaultConfiguration parent = new VaultConfiguration("http://vault-url.com/", null);
        assertThat(parent.getVaultUrl(), is("http://vault-url.com"));
    }

    public void shouldCorrectlyShowIfEmpty() {

    }
}
