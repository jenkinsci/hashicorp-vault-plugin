package com.datapipe.jenkins.vault.jcasc.secrets;

import java.util.Objects;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.ProtectedExternally;

@Restricted(ProtectedExternally.class)
public class VaultAppRole {

    private String appRole;
    private String appRoleSecret;

    public VaultAppRole(String appRole, String appRoleSecret) {
        this.appRole = appRole;
        this.appRoleSecret = appRoleSecret;
    }

    public String getAppRole() {
        return appRole;
    }

    public String getAppRoleSecret() {
        return appRoleSecret;
    }

    @Override
    public int hashCode() {
        return Objects.hash(appRole, appRoleSecret);
    }
}
