package com.datapipe.jenkins.vault;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.datapipe.jenkins.vault.WindowsFilePermissionHelper.ACL_ENTRY_PERMISSIONS;
import static com.datapipe.jenkins.vault.WindowsFilePermissionHelper.fixSshKeyOnWindows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WindowsFilePermissionsTest {

    private Path file;
    private AclFileAttributeView fileAttributeView;
    private UserPrincipal userPrincipal;

    @BeforeEach
    void beforeEach() throws Exception {
        assumeTrue(isWindows());
        file = Files.createTempFile("permission-test-", "");
        fileAttributeView = Files.getFileAttributeView(file, AclFileAttributeView.class);
        assertNotNull(fileAttributeView);
        userPrincipal = fileAttributeView.getOwner();
        assertNotNull(userPrincipal);
    }

    @AfterEach
    void afterEach() throws Exception {
        if (file != null) {
            Files.deleteIfExists(file);
        }
    }

    @Test
    void test_windows_file_permission_is_set_correctly() throws Exception {
        fixSshKeyOnWindows(file);
        assertEquals(1, fileAttributeView.getAcl().size());
        AclEntry aclEntry = fileAttributeView.getAcl().get(0);
        assertTrue(aclEntry.flags().isEmpty());
        assertEquals(ACL_ENTRY_PERMISSIONS, aclEntry.permissions());
        assertEquals(userPrincipal, aclEntry.principal());
        assertEquals(AclEntryType.ALLOW, aclEntry.type());
    }

    @Test
    void test_windows_file_permission_are_incorrect() throws Exception {
        // By default files include System and builtin administrators
        assertNotSame(1, fileAttributeView.getAcl().size());
        for (AclEntry entry : fileAttributeView.getAcl()) {
            if (entry.principal().equals(userPrincipal)) {
                assertNotSame(ACL_ENTRY_PERMISSIONS, entry.permissions());
            }
        }
    }

    /** inline ${@link hudson.Functions#isWindows()} to prevent a transient remote classloader issue */
    private boolean isWindows() {
        return File.pathSeparatorChar == ';';
    }
}
