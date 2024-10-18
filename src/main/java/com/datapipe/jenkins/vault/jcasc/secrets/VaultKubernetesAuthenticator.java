package com.datapipe.jenkins.vault.jcasc.secrets;

import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class VaultKubernetesAuthenticator extends VaultAuthenticatorWithExpiration {
    private final static Logger LOGGER = Logger.getLogger(VaultKubernetesAuthenticator.class.getName());

    private static final String SERVICE_ACCOUNT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private VaultKubernetes kubernetes;

    private String mountPath;

    private String jwt;

    public VaultKubernetesAuthenticator(VaultKubernetes kubernetes, String mountPath) {
        this.kubernetes = kubernetes;
        this.mountPath = mountPath;
    }

    @SuppressFBWarnings(value = "DMI_HARDCODED_ABSOLUTE_FILENAME")
    public void authenticate(Vault vault, VaultConfig config) throws VaultException, VaultPluginException {
        if (isTokenTTLExpired()) {
            try (Stream<String> input =  Files.lines(Paths.get(SERVICE_ACCOUNT_TOKEN_PATH)) ) {
                this.jwt = input.collect(Collectors.joining());
            } catch (IOException e) {
                throw new VaultPluginException("could not get JWT from Service Account Token", e);
            }
            // authenticate
            currentAuthToken = vault.auth()
                .loginByJwt(mountPath, kubernetes.getRole(), this.jwt)
                .getAuthClientToken();
            config.token(currentAuthToken).build();
            LOGGER.log(Level.FINE, "Login to Vault using Kubernetes successful");
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
        return Objects.hash(kubernetes);
    }
}
