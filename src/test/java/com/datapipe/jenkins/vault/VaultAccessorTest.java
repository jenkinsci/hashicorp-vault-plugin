package com.datapipe.jenkins.vault;

import hudson.EnvVars;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class VaultAccessorTest {

    private static final String POLICIES_STR =
        "\npol1\n\nbase_${job_base_name}\njob/${job_name}\n job_${job_name_us}\nfolder/${job_folder}\nfolder_${job_folder_us}\nnode_${node_name}\n";

    @Test
    void testGeneratePolicies() {
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
    void testGeneratePoliciesWithFolder() {
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
