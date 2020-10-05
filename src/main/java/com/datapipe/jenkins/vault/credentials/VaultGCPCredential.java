package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Auth;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import org.kohsuke.stapler.DataBoundConstructor;

public class VaultGCPCredential extends AbstractAuthenticatingVaultTokenCredential {

    @NonNull
    private final String role;
    @NonNull
    private final String audience;

    @DataBoundConstructor
    public VaultGCPCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id,
        @CheckForNull String description, @NonNull String role, @NonNull String audience) {
        super(scope, id, description);
        this.role = role;
        this.audience = audience;
    }

    @NonNull
    public String getRole() {
        return role;
    }

    @NonNull
    public String getAudience() {
        return audience;
    }

    @Override
    public String getToken(Auth auth) {
        String jwt;
        try {
            jwt = retrieveGoogleJWT();
        } catch (URISyntaxException | IOException e) {
            throw new VaultPluginException("could not get JWT from GCP metadata", e);
        }

        try {
            return auth.loginByGCP(role, jwt).getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault", e);
        }
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Vault GCP Credential";
        }

    }

    private String retrieveGoogleJWT() throws URISyntaxException, IOException {
        final String HTTP_SCHEME = "http";
        final String NO_USER_INFO = null;
        final String METADATA_HOST_ADDRESS = "metadata";
        final int UNSPECIFIED_PORT = -1;
        final String METADATA_PATH = "/computeMetadata/v1/instance/"
            + "service-accounts/default/identity";
        final String FRAGMENT = null;

        // TODO: would like to pull the get the audience from the plugin config
        // instead of specifying it each Vault GCP credential
        String query = "audience=" + audience + "&format=full";
        URL website = new URI(HTTP_SCHEME, NO_USER_INFO, METADATA_HOST_ADDRESS, UNSPECIFIED_PORT,
            METADATA_PATH, query, FRAGMENT).toURL();
        URLConnection connection = website.openConnection();
        HttpURLConnection httpConnection = safelyCastToHttpUrlConnection(connection);
        httpConnection.setRequestProperty("Metadata-Flavor", "Google");

        return download(httpConnection);
    }

    private static HttpURLConnection safelyCastToHttpUrlConnection(URLConnection connection) {
        if (connection instanceof HttpURLConnection) {
            return (HttpURLConnection) connection;
        } else {
            throw new RuntimeException("We do not have Http connection, but we used http schema");
        }
    }

    private static String download(URLConnection connection) throws IOException {
        try (BufferedReader in = new BufferedReader(
            new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            in.lines().forEachOrdered(sb::append);
            return sb.toString();
        }
    }
}
