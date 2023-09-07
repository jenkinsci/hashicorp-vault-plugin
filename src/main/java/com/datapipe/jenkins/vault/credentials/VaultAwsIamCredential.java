package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.api.Auth;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.AwsHelper;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import static org.apache.commons.lang.StringUtils.defaultIfBlank;

public class VaultAwsIamCredential extends AbstractAuthenticatingVaultTokenCredential {

    @NonNull
    private String role = "";

    private String targetIamRole = "";

    @NonNull
    private String serverId = "";

    @NonNull
    private String mountPath = DescriptorImpl.defaultMountPath;

    @DataBoundConstructor
    public VaultAwsIamCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                                 @CheckForNull String description) {
        super(scope, id, description);
    }

    @NonNull
    public String getRole() {
        return this.role;
    }

    @DataBoundSetter
    public void setRole(@NonNull String role) {
        this.role = role;
    }

    public String getTargetIamRole() {
        return targetIamRole;
    }

    @DataBoundSetter
    public void setTargetIamRole(String targetIamRole) {
        this.targetIamRole = targetIamRole;
    }

    @NonNull
    public String getServerId() {
        return this.serverId;
    }

    @DataBoundSetter
    public void setServerId(@NonNull String serverId) {
        this.serverId = serverId;
    }

    @NonNull
    public String getMountPath() {
        return this.mountPath;
    }

    @DataBoundSetter
    public void setMountPath(@NonNull String mountPath) {
        this.mountPath = defaultIfBlank(mountPath, DescriptorImpl.defaultMountPath);
    }

    @Override
    public String getToken(Auth auth) {
        return AwsHelper.getToken(auth, null, this.role, this.targetIamRole, this.serverId, this.mountPath);
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return "Vault AWS IAM Credential";
        }

        public static final String defaultMountPath = "aws";
    }
}
