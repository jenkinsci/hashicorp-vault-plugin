package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultException;
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

public class VaultAWSCredential extends AbstractVaultTokenCredential {

    private static final String METADATA_HTTP_SCHEME = "http";
    private static final String METADATA_HOST_ADDRESS = "169.254.169.254";
    private static final String METADATA_PATH = "/latest/dynamic/instance-identity/pkcs7";

    @NonNull
    private final String role;
    @NonNull
    private final String awsMountPath;
    @NonNull
    private final String nonce;

    @DataBoundConstructor
    public VaultAWSCredential(
                            @CheckForNull CredentialsScope scope,
                            @CheckForNull String id,
                            @CheckForNull String description,
                            @NonNull String role,
                            @NonNull String awsMountPath,
                            @NonNull String nonce) {
        super(scope, id, description);
        this.role = role;
        this.awsMountPath = awsMountPath;
        this.nonce = nonce;
    }

    @NonNull
    public String getRole() {
        return role;
    }

    @Override
    public String getToken(Vault vault) {
        String pkcs7;
        try {
            pkcs7 = retrieveAWSPKCS7();
        } catch (URISyntaxException | IOException e) {
            throw new VaultPluginException("could not get pkcs7 from AWS metadata", e);
        }

        try {
            return vault.withRetries(5, 500).auth().loginByAwsEc2(role, pkcs7, nonce, awsMountPath).getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault", e);
        }
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Vault AWS EC2 Credential";
        }

    }

    private String retrieveAWSPKCS7() throws URISyntaxException, IOException {
        URL url = new URI(METADATA_HTTP_SCHEME, METADATA_HOST_ADDRESS, METADATA_PATH, null).toURL();
        URLConnection connection = url.openConnection();
        HttpURLConnection httpConnection = safelyCastToHttpUrlConnection(connection);

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
