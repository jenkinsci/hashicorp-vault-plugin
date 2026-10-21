package com.datapipe.jenkins.vault.credentials.common;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.util.List;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link VaultPKICredentialsBinding}.
 */
public class VaultPKICredentialsBindingTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void restrictToOwnerOnWindows_rejectsFileSystemsWithoutAcls_elseRestrictsToOwner()
        throws Exception {
        File keyFile = tmp.newFile("vault-pki-key.pem");
        AclFileAttributeView aclView =
            Files.getFileAttributeView(keyFile.toPath(), AclFileAttributeView.class);
        VaultPKICredentialsBinding.RestrictToOwnerOnWindows restrict =
            new VaultPKICredentialsBinding.RestrictToOwnerOnWindows();

        if (aclView == null) {
            // e.g. Linux/macOS, FAT32/exFAT: owner-only access cannot be enforced via ACLs, so the
            // binding must refuse instead of silently writing the key unprotected
            IOException ex = assertThrows(IOException.class, () -> restrict.invoke(keyFile, null));
            assertTrue(ex.getMessage(), ex.getMessage().contains("does not support access control"));
        } else {
            // NTFS: the ACL is reduced to a single entry for the file owner
            restrict.invoke(keyFile, null);
            List<AclEntry> acl = aclView.getAcl();
            assertEquals("only the owner may access the key file", 1, acl.size());
            assertEquals(aclView.getOwner(), acl.get(0).principal());
        }
    }
}
