package com.datapipe.jenkins.vault.jcasc.secrets;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.datapipe.jenkins.vault.AwsHelper;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public class VaultAwsIamAuthenticator extends VaultAuthenticatorWithExpiration {
    private final static Logger LOGGER = Logger.getLogger(VaultAwsIamAuthenticator.class.getName());

    @NonNull
    private VaultAwsIam awsIam;

    @NonNull
    private String mountPath;

    public VaultAwsIamAuthenticator(@NonNull VaultAwsIam awsIam, @NonNull String mountPath) {
        this.awsIam = awsIam;
        this.mountPath = mountPath;
    }

    public void authenticate(@NonNull Vault vault, @NonNull VaultConfig config) throws VaultException, VaultPluginException {
        if (isTokenTTLExpired()) {
            // authenticate
            currentAuthToken = AwsHelper.getToken(vault.auth(), null, awsIam.getRole(), awsIam.getTargetIAMRole(), awsIam.getServerId(), mountPath);
            config.token(currentAuthToken).build();
            LOGGER.log(Level.FINE, "Login to Vault using AWS IAM successful");
            getTTLExpiryOfCurrentToken(vault);
        } else {
            // make sure current auth token is set in config
            config.token(currentAuthToken).build();
        }
    }

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return Objects.hash(awsIam);
    }
}
