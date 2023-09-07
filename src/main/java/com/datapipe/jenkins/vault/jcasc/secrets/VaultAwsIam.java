package com.datapipe.jenkins.vault.jcasc.secrets;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.ProtectedExternally;

@Restricted(ProtectedExternally.class)
public class VaultAwsIam {

    @NonNull
    private String role;

    private String targetIamRole;

    @NonNull
    private String serverId;

    public VaultAwsIam(@NonNull String role, String targetIamRole, @NonNull String serverId) {
        this.role = role;
        this.serverId = serverId;
        this.targetIamRole = targetIamRole;
    }

    @NonNull
    public String getRole() {
        return role;
    }

    public String getTargetIAMRole() {
        return targetIamRole;
    }

    @NonNull
    public String getServerId() {
        return serverId;
    }

    @Override
    public int hashCode() {
        return Objects.hash(role, serverId);
    }
}
