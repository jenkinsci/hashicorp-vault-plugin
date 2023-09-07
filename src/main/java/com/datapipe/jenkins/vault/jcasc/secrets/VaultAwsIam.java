package com.datapipe.jenkins.vault.jcasc.secrets;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.ProtectedExternally;

@Restricted(ProtectedExternally.class)
public class VaultAwsIam {

    @NonNull
    private String role;
    
    @NonNull
    private String target_iam_role;

    @NonNull
    private String serverId;

    public VaultAwsIam(@NonNull String role, @NonNull String serverId) {
        this.role = role;
        this.serverId = serverId;
    }

    @NonNull
    public String getRole() {
        return role;
    }
    
    @NonNull
    public String getTargetIAMRole() {
        return target_iam_role;
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
