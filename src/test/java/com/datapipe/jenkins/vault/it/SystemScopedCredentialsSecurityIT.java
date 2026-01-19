package com.datapipe.jenkins.vault.it;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsUnavailableException;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.VaultAccessor;
import com.datapipe.jenkins.vault.configuration.VaultConfiguration;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import hudson.util.Secret;
import java.util.Collections;
import java.util.List;
import jenkins.model.Jenkins;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for CVE-2025-67642: System-scoped credentials should not be accessible
 * from item/folder contexts, only from global context.
 */
public class SystemScopedCredentialsSecurityIT {

    private static final String SYSTEM_SCOPED_CREDENTIAL_ID = "system-scoped-credential";
    private static final String GLOBAL_SCOPED_CREDENTIAL_ID = "global-scoped-credential";

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    private VaultCredential systemScopedCredential;
    private VaultCredential globalScopedCredential;
    private FreeStyleProject project;
    private Folder folder;

    @Before
    public void setupJenkins() throws Exception {
        // Create System-scoped credential (should only be accessible from global context)
        systemScopedCredential = new VaultTokenCredential(
            CredentialsScope.SYSTEM,
            SYSTEM_SCOPED_CREDENTIAL_ID,
            "System-scoped credential for global configuration only",
            Secret.fromString("system-token")
        );

        // Create Global-scoped credential (should be accessible from any context)
        globalScopedCredential = new VaultTokenCredential(
            CredentialsScope.GLOBAL,
            GLOBAL_SCOPED_CREDENTIAL_ID,
            "Global-scoped credential",
            Secret.fromString("global-token")
        );

        // Add both credentials to SystemCredentialsProvider
        SystemCredentialsProvider.getInstance().setDomainCredentialsMap(
            Collections.singletonMap(
                Domain.global(),
                java.util.Arrays.asList(systemScopedCredential, globalScopedCredential)
            )
        );

        // Create a folder and a project in it
        folder = jenkins.createProject(Folder.class, "test-folder");
        project = folder.createProject(FreeStyleProject.class, "test-project");
    }

    /**
     * Test that System-scoped credentials are NOT accessible from Job context.
     * This verifies the fix for CVE-2025-67642.
     */
    @Test
    public void systemScopedCredentialShouldNotBeAccessibleFromJobContext() throws Exception {
        // Try to retrieve System-scoped credential from Job context
        VaultConfiguration config = new VaultConfiguration();
        config.setVaultCredentialId(SYSTEM_SCOPED_CREDENTIAL_ID);

        FreeStyleBuild build = mock(FreeStyleBuild.class);
        when(build.getParent()).thenReturn(project);

        // This should throw CredentialsUnavailableException because System-scoped
        // credentials should not be accessible from Job context
        try {
            VaultCredential credential = VaultAccessor.retrieveVaultCredentials(build, config);
            // If we get here, the vulnerability is present - credential should be null or throw exception
            assertThat("System-scoped credential should not be accessible from Job context",
                credential, is(nullValue()));
        } catch (CredentialsUnavailableException e) {
            // Expected behavior - credential is not available
            assertThat("Exception message should contain credential ID",
                e.getMessage(), is(notNullValue()));
        } catch (VaultPluginException e) {
            // Also acceptable - credential lookup failed
            assertThat("Exception message should not be empty",
                e.getMessage(), is(notNullValue()));
        }
    }

    /**
     * Test that System-scoped credentials are NOT accessible from Folder context.
     */
    @Test
    public void systemScopedCredentialShouldNotBeAccessibleFromFolderContext() {
        // Try to lookup System-scoped credential from Folder context
        List<VaultCredential> credentials = CredentialsProvider.lookupCredentialsInItemGroup(
            VaultCredential.class,
            folder,
            ACL.SYSTEM2,
            Collections.emptyList()
        );

        // Filter for System-scoped credential
        VaultCredential found = credentials.stream()
            .filter(c -> SYSTEM_SCOPED_CREDENTIAL_ID.equals(c.getId()))
            .findFirst()
            .orElse(null);

        // System-scoped credential should NOT be in the list
        assertThat("System-scoped credential should not be accessible from Folder context",
            found, is(nullValue()));
    }

    /**
     * Test that System-scoped credentials ARE accessible from global context.
     */
    @Test
    public void systemScopedCredentialShouldBeAccessibleFromGlobalContext() {
        // Try to lookup System-scoped credential from global context
        List<VaultCredential> credentials = CredentialsProvider.lookupCredentialsInItemGroup(
            VaultCredential.class,
            Jenkins.get(), // Global context
            ACL.SYSTEM2,
            Collections.emptyList()
        );

        // Filter for System-scoped credential
        VaultCredential found = credentials.stream()
            .filter(c -> SYSTEM_SCOPED_CREDENTIAL_ID.equals(c.getId()))
            .findFirst()
            .orElse(null);

        // System-scoped credential SHOULD be in the list when accessed from global context
        assertThat("System-scoped credential should be accessible from global context",
            found, is(notNullValue()));
        assertThat("Found credential should have correct ID",
            found.getId(), is(SYSTEM_SCOPED_CREDENTIAL_ID));
    }

    /**
     * Test that Global-scoped credentials ARE accessible from Job context.
     * This ensures we didn't break normal functionality.
     */
    @Test
    public void globalScopedCredentialShouldBeAccessibleFromJobContext() {
        // Try to lookup Global-scoped credential from Job context
        List<VaultCredential> credentials = CredentialsProvider.lookupCredentialsInItem(
            VaultCredential.class,
            project,
            ACL.SYSTEM2,
            Collections.emptyList()
        );

        // Filter for Global-scoped credential
        VaultCredential found = credentials.stream()
            .filter(c -> GLOBAL_SCOPED_CREDENTIAL_ID.equals(c.getId()))
            .findFirst()
            .orElse(null);

        // Global-scoped credential SHOULD be in the list
        assertThat("Global-scoped credential should be accessible from Job context",
            found, is(notNullValue()));
        assertThat("Found credential should have correct ID",
            found.getId(), is(GLOBAL_SCOPED_CREDENTIAL_ID));
    }

    /**
     * Test that Global-scoped credentials ARE accessible from Folder context.
     */
    @Test
    public void globalScopedCredentialShouldBeAccessibleFromFolderContext() {
        // Try to lookup Global-scoped credential from Folder context
        List<VaultCredential> credentials = CredentialsProvider.lookupCredentialsInItemGroup(
            VaultCredential.class,
            folder,
            ACL.SYSTEM2,
            Collections.emptyList()
        );

        // Filter for Global-scoped credential
        VaultCredential found = credentials.stream()
            .filter(c -> GLOBAL_SCOPED_CREDENTIAL_ID.equals(c.getId()))
            .findFirst()
            .orElse(null);

        // Global-scoped credential SHOULD be in the list
        assertThat("Global-scoped credential should be accessible from Folder context",
            found, is(notNullValue()));
        assertThat("Found credential should have correct ID",
            found.getId(), is(GLOBAL_SCOPED_CREDENTIAL_ID));
    }

    /**
     * Test that VaultCredentialsProvider correctly filters System-scoped credentials
     * based on context.
     */
    @Test
    public void vaultCredentialsProviderShouldFilterSystemScopedCredentialsByContext() {
        // Test from Job context - should NOT include System-scoped
        List<VaultCredential> jobCredentials = CredentialsProvider.lookupCredentialsInItem(
            VaultCredential.class,
            project,
            ACL.SYSTEM2,
            Collections.emptyList()
        );

        long systemScopedCount = jobCredentials.stream()
            .filter(c -> CredentialsScope.SYSTEM.equals(c.getScope()))
            .count();

        assertThat("Job context should not have System-scoped credentials",
            systemScopedCount, is(0L));

        // Test from Folder context - should NOT include System-scoped
        List<VaultCredential> folderCredentials = CredentialsProvider.lookupCredentialsInItemGroup(
            VaultCredential.class,
            folder,
            ACL.SYSTEM2,
            Collections.emptyList()
        );

        systemScopedCount = folderCredentials.stream()
            .filter(c -> CredentialsScope.SYSTEM.equals(c.getScope()))
            .count();

        assertThat("Folder context should not have System-scoped credentials",
            systemScopedCount, is(0L));

        // Test from global context - SHOULD include System-scoped
        List<VaultCredential> globalCredentials = CredentialsProvider.lookupCredentialsInItemGroup(
            VaultCredential.class,
            Jenkins.get(),
            ACL.SYSTEM2,
            Collections.emptyList()
        );

        systemScopedCount = globalCredentials.stream()
            .filter(c -> CredentialsScope.SYSTEM.equals(c.getScope()))
            .count();

        assertThat("Global context should have System-scoped credentials",
            systemScopedCount, is(1L));
    }
}
