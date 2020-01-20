package com.datapipe.jenkins.vault.jcasc.secrets;

import java.util.Objects;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.ProtectedExternally;


@Restricted(ProtectedExternally.class)
public class VaultKubernetes {
    private String role;

    public VaultKubernetes(String role) {
        this.role = role;
    }

    public String getRole() {
        return role;
    }

    @Override
    public int hashCode() {
        return Objects.hash(role);
    }
}
