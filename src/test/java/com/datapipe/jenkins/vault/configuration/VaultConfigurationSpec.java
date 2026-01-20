package com.datapipe.jenkins.vault.configuration;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class VaultConfigurationSpec {

    public static VaultConfiguration completeTestConfig(String identifier, Integer engineVersion) {
        VaultConfiguration result = new VaultConfiguration();
        result.setVaultUrl("http://example.com/" + identifier);
        result.setVaultCredentialId("credential" + identifier);
        result.setEngineVersion(engineVersion);
        return result;
    }

    public static VaultConfiguration completeTestConfig(String identifier) {
        return completeTestConfig(identifier, 2);
    }

    public static VaultConfiguration urlOnlyConfig(String identifier) {
        VaultConfiguration result = new VaultConfiguration();
        result.setVaultUrl("http://example.com/" + identifier);
        return result;
    }

    public static VaultConfiguration credentialOnlyConfig(String identifier) {
        VaultConfiguration result = new VaultConfiguration();
        result.setVaultCredentialId("credential" + identifier);
        return result;
    }

    @Test
    void childShouldCompletelyOverwriteParent() {
        VaultConfiguration parent = completeTestConfig("parent");
        VaultConfiguration child = completeTestConfig("child");
        VaultConfiguration result = child.mergeWithParent(parent);

        assertThat(result.getVaultCredentialId(), is(child.getVaultCredentialId()));
        assertThat(result.getVaultUrl(), is(child.getVaultUrl()));
    }

    @Test
    void childShouldPartlyOverwriteParent() {
        VaultConfiguration parent = completeTestConfig("parent");
        VaultConfiguration child = urlOnlyConfig("child");
        VaultConfiguration result = child.mergeWithParent(parent);

        assertThat(result.getVaultCredentialId(), is(parent.getVaultCredentialId()));
        assertThat(result.getVaultUrl(), is(child.getVaultUrl()));

        parent = completeTestConfig("parent");
        child = credentialOnlyConfig("child");
        result = child.mergeWithParent(parent);

        assertThat(result.getVaultCredentialId(), is(child.getVaultCredentialId()));
        assertThat(result.getVaultUrl(), is(parent.getVaultUrl()));
    }

    @Test
    void emptyChildShouldBeOverridden() {
        VaultConfiguration parent = completeTestConfig("parent");
        VaultConfiguration child = new VaultConfiguration();
        VaultConfiguration result = child.mergeWithParent(parent);

        assertThat(result.getVaultCredentialId(), is(parent.getVaultCredentialId()));
        assertThat(result.getVaultUrl(), is(parent.getVaultUrl()));
    }

    @Test
    void emptyParentShouldBeIgnored() {
        VaultConfiguration parent = new VaultConfiguration();
        VaultConfiguration child = completeTestConfig("child");
        VaultConfiguration result = child.mergeWithParent(parent);

        assertThat(result.getVaultCredentialId(), is(child.getVaultCredentialId()));
        assertThat(result.getVaultUrl(), is(child.getVaultUrl()));
    }

    @Test
    void shouldHandleNull() {
        VaultConfiguration dummy = completeTestConfig("dummy");
        VaultConfiguration result = dummy.mergeWithParent(null);

        assertThat(result.getVaultCredentialId(), is(dummy.getVaultCredentialId()));
        assertThat(result.getVaultUrl(), is(dummy.getVaultUrl()));
    }

    @Test
    void shouldNotStoreTrailingSlashesInUrl() {
        VaultConfiguration parent = new VaultConfiguration();
        parent.setVaultUrl("http://vault-url.com/");
        parent.setFailIfNotFound(false);
        parent.setVaultNamespace("mynamespace");
        parent.setTimeout(20);
        assertThat(parent.getVaultUrl(), is("http://vault-url.com"));
    }

    @Test
    void shouldStoreFailureHandling() {
        VaultConfiguration parent = new VaultConfiguration();
        parent.setVaultUrl("http://vault-url.com/");
        parent.setFailIfNotFound(false);
        parent.setVaultNamespace("mynamespace");
        parent.setTimeout(20);
        assertThat(parent.getFailIfNotFound(), is(false));
    }

    @Test
    void shouldStorePrefixPath() {
        VaultConfiguration parent = new VaultConfiguration();
        parent.setVaultUrl("http://vault-url.com/");
        parent.setFailIfNotFound(false);
        parent.setPrefixPath("my/custom/prefixpath");
        parent.setTimeout(20);
        assertThat(parent.getPrefixPath(), is("my/custom/prefixpath"));
    }
}
