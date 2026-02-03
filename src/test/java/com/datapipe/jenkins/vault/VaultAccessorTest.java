package com.datapipe.jenkins.vault;

import hudson.EnvVars;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class VaultAccessorTest {

    private static final String POLICIES_STR =
        "\npol1\n\nbase_${job_base_name}\njob/${job_name}\n job_${job_name_us}\nfolder/${job_folder}\nfolder_${job_folder_us}\nnode_${node_name}\n";

    @Mock private Vault mockVault;
    @Mock private Logical mockLogical;
    @Mock private LogicalResponse mockResponse;

    @Test
    public void normalizePathStripsLeadingAndDuplicateSlashes() {
        assertEquals("github/token/foo", VaultAccessor.normalizePath("/github//token/foo"));
        assertEquals("prefix/bar/baz", VaultAccessor.normalizePath("///prefix//bar//baz"));
    }

    @Test
    public void readUsesNormalizedPath() throws Exception {
        VaultAccessor accessor = new VaultAccessor();

        when(mockVault.logical()).thenReturn(mockLogical);
        when(mockLogical.read("github/token/foo")).thenReturn(mockResponse);

        Field vaultField = VaultAccessor.class.getDeclaredField("vault");
        vaultField.setAccessible(true);
        vaultField.set(accessor, mockVault);

        accessor.read("/github//token/foo", 1);

        verify(mockLogical).read("github/token/foo");
    }

    @Test
    public void testGeneratePolicies() {
        EnvVars envVars = mock(EnvVars.class);
        when(envVars.get("JOB_NAME")).thenReturn("job1");
        when(envVars.get("JOB_BASE_NAME")).thenReturn("job1");
        when(envVars.get("NODE_NAME")).thenReturn("node1");

        List<String> policies = VaultAccessor.generatePolicies(POLICIES_STR, envVars);
        assertThat(policies, equalTo(Arrays.asList(
            "pol1", "base_job1", "job/job1", "job_job1", "folder/", "folder_", "node_node1"
        )));
    }

    @Test
    public void testGeneratePoliciesWithFolder() {
        EnvVars envVars = mock(EnvVars.class);
        when(envVars.get("JOB_NAME")).thenReturn("folder1/folder2/job1");
        when(envVars.get("JOB_BASE_NAME")).thenReturn("job1");
        when(envVars.get("NODE_NAME")).thenReturn("node1");

        List<String> policies = VaultAccessor.generatePolicies(POLICIES_STR, envVars);
        assertThat(policies, equalTo(Arrays.asList(
            "pol1", "base_job1", "job/folder1/folder2/job1", "job_folder1_folder2_job1",
            "folder/folder1/folder2", "folder_folder1_folder2", "node_node1"
        )));
    }
}
