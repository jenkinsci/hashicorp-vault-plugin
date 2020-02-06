package com.datapipe.jenkins.vault;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.util.Collections;
import java.util.EnumSet;

public class WindowsFilePermissionHelper {

    public static final EnumSet<AclEntryPermission> ACL_ENTRY_PERMISSIONS = EnumSet.of(
        AclEntryPermission.READ_DATA,
        AclEntryPermission.WRITE_DATA,
        AclEntryPermission.APPEND_DATA,
        AclEntryPermission.READ_NAMED_ATTRS,
        AclEntryPermission.WRITE_NAMED_ATTRS,
        AclEntryPermission.EXECUTE,
        AclEntryPermission.READ_ATTRIBUTES,
        AclEntryPermission.WRITE_ATTRIBUTES,
        AclEntryPermission.DELETE,
        AclEntryPermission.READ_ACL,
        AclEntryPermission.SYNCHRONIZE
    );

    public static void fixSshKeyOnWindows(Path file) {
        AclFileAttributeView fileAttributeView = Files
            .getFileAttributeView(file, AclFileAttributeView.class);
        if (fileAttributeView == null) return;

        try {
            UserPrincipal userPrincipal = fileAttributeView.getOwner();
            AclEntry aclEntry = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(userPrincipal)
                .setPermissions(ACL_ENTRY_PERMISSIONS)
                .build();
            fileAttributeView.setAcl(Collections.singletonList(aclEntry));
        } catch (IOException | UnsupportedOperationException e) {
            throw new IllegalStateException("Error updating file permission for \"" + file + "\"", e);
        }
    }
}
