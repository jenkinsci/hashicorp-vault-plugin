package com.datapipe.jenkins.vault.it;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import hudson.model.FreeStyleProject;
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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Test for CVE-2025-67642: Top-level jobs should not see system-scoped credentials.
 */
public class TopLevelJobSecurityTest {

    private static final String SYSTEM_SCOPED_CREDENTIAL_ID = "system-scoped-credential";
    private static final String GLOBAL_SCOPED_CREDENTIAL_ID = "global-scoped-credential";

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    private FreeStyleProject topLevelProject;

    @Before
    public void setupJenkins() throws Exception {
        // Create System-scoped credential (should NOT be accessible from jobs)
        VaultCredential systemScopedCredential = new VaultTokenCredential(
            CredentialsScope.SYSTEM,
            SYSTEM_SCOPED_CREDENTIAL_ID,
            "System-scoped credential",
            Secret.fromString("system-token")
        );

        // Create Global-scoped credential (SHOULD be accessible from jobs)
        VaultCredential globalScopedCredential = new VaultTokenCredential(
            CredentialsScope.GLOBAL,
            GLOBAL_SCOPED_CREDENTIAL_ID,
            "Global-scoped credential",
            Secret.fromString("global-token")
        );

        SystemCredentialsProvider.getInstance().setDomainCredentialsMap(
            Collections.singletonMap(Domain.global(),
                java.util.Arrays.asList(systemScopedCredential, globalScopedCredential))
        );

        // Create a TOP-LEVEL job (NOT inside a folder)
        topLevelProject = jenkins.createFreeStyleProject("top-level-project");
    }

    @Test
    public void systemScopedCredentialShouldNotBeAccessibleFromTopLevelJob() {
        // Verify the project parent is Jenkins.get() (not a folder)
        assertThat("Top-level project parent should be Jenkins instance",
            topLevelProject.getParent() == Jenkins.get(), is(true));

        // Try to lookup credentials from top-level job context
        List<VaultCredential> credentials = CredentialsProvider.lookupCredentialsInItem(
            VaultCredential.class,
            topLevelProject,
            ACL.SYSTEM2,
            Collections.emptyList()
        );

        // Count System-scoped credentials
        long systemScopedCount = credentials.stream()
            .filter(c -> CredentialsScope.SYSTEM.equals(c.getScope()))
            .count();

        // This should be 0, but the vulnerability makes it 1
        System.out.println("System-scoped credentials found in top-level job context: " + systemScopedCount);
        System.out.println("Credentials found: " + credentials);

        assertThat("Top-level job should NOT have access to System-scoped credentials",
            systemScopedCount, is(0L));
    }

    @Test
    public void globalScopedCredentialShouldBeAccessibleFromTopLevelJob() {
        // Verify the project parent is Jenkins.get() (not a folder)
        assertThat("Top-level project parent should be Jenkins instance",
            topLevelProject.getParent() == Jenkins.get(), is(true));

        // Try to lookup credentials from top-level job context
        List<VaultCredential> credentials = CredentialsProvider.lookupCredentialsInItem(
            VaultCredential.class,
            topLevelProject,
            ACL.SYSTEM2,
            Collections.emptyList()
        );

        // Find Global-scoped credential
        VaultCredential found = credentials.stream()
            .filter(c -> GLOBAL_SCOPED_CREDENTIAL_ID.equals(c.getId()))
            .findFirst()
            .orElse(null);

        // Global-scoped credential SHOULD be accessible
        assertThat("Global-scoped credential should be accessible from top-level job",
            found, is(notNullValue()));
        assertThat("Found credential should have correct ID",
            found.getId(), is(GLOBAL_SCOPED_CREDENTIAL_ID));
    }
}
