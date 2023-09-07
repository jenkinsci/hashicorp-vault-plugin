package com.datapipe.jenkins.vault;

import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.http.HttpMethodName;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.util.RuntimeHttpUtils;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Auth;
import com.bettercloud.vault.json.JsonArray;
import com.bettercloud.vault.json.JsonObject;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;


public class AwsHelper {

    private final static Logger LOGGER = Logger.getLogger(AwsHelper.class.getName());

    @NonNull
    public static String getToken(@NonNull Auth auth, @CheckForNull AWSCredentials credentials,
                                  @CheckForNull String role, @CheckForNull String targetIamRole, @CheckForNull String serverIdValue,
                                  @CheckForNull String mountPath) throws VaultPluginException {
        final EncodedIdentityRequest request;
        try {
            request = new EncodedIdentityRequest(credentials, targetIamRole, serverIdValue);
        } catch (IOException | URISyntaxException e) {
            throw new VaultPluginException("could not get IAM request from AWS metadata", e);
        }

        // Convert empty role and mount to null so loginByAwsIam uses the defaults
        final String requestRole = Util.fixEmptyAndTrim(role);
        final String requestMountPath = Util.fixEmptyAndTrim(mountPath);
        try {
            return auth.loginByAwsIam(requestRole, request.encodedUrl, request.encodedBody,
                                      request.encodedHeaders, requestMountPath)
                .getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("could not log in into vault", e);
        }
    }

    private static class EncodedIdentityRequest {

        @NonNull
        public final String encodedHeaders;

        @NonNull
        public final String encodedBody;

        @NonNull
        public final String encodedUrl;

        private static final String data = "Action=GetCallerIdentity&Version=2011-06-15";
        private static final String endpoint = "https://sts.amazonaws.com";
        private static final String vault_session_name = "vault-jenkins";

        EncodedIdentityRequest(@CheckForNull AWSCredentials credentials, @CheckForNull String targetIamRole, @CheckForNull String serverIdValue) throws IOException, URISyntaxException {
            LOGGER.fine("Creating GetCallerIdentity request");
            final DefaultRequest request = new DefaultRequest("sts");
            request.addHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
            if (StringUtils.isNotEmpty(serverIdValue)) {
                request.addHeader("X-Vault-AWS-IAM-Server-ID", serverIdValue);
            }
            request.setContent(new ByteArrayInputStream(this.data.getBytes(StandardCharsets.UTF_8)));
            request.setHttpMethod(HttpMethodName.POST);
            request.setEndpoint(new URI(this.endpoint));

            if (credentials == null) {
                LOGGER.fine("Acquiring AWS credentials");
                if (targetIamRole == null || targetIamRole.isEmpty()) {
                    credentials = new DefaultAWSCredentialsProviderChain().getCredentials();
                } else {
                    AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard().withCredentials(new DefaultAWSCredentialsProviderChain()).build();
                    STSAssumeRoleSessionCredentialsProvider assumedCred = new STSAssumeRoleSessionCredentialsProvider.Builder(targetIamRole, vault_session_name).withStsClient(stsClient).build();
                    credentials = assumedCred.getCredentials();
                }
                LOGGER.log(Level.FINER, "AWS Access Key ID: {0}", credentials.getAWSAccessKeyId());
            }

            LOGGER.fine("Signing GetCallerIdentity request");
            final AWS4Signer aws4Signer = new AWS4Signer();
            aws4Signer.setServiceName(request.getServiceName());
            aws4Signer.sign(request, credentials);

            final Base64.Encoder encoder = Base64.getEncoder();

            final JsonObject headers = new JsonObject();
            final Map<String, String> headersMap = getHeadersMap(request);
            for (Map.Entry<String, String> entry : headersMap.entrySet()) {
                final JsonArray array = new JsonArray();
                array.add(entry.getValue());
                headers.add(entry.getKey(), array);
            }
            encodedHeaders = encoder.encodeToString(headers.toString().getBytes(StandardCharsets.UTF_8));

            final byte[] body = IOUtils.toByteArray(request.getContent());
            encodedBody = encoder.encodeToString(body);

            final URL url = RuntimeHttpUtils.convertRequestToUrl(request, true, true);
            encodedUrl = encoder.encodeToString(url.toString().getBytes(StandardCharsets.UTF_8));
        }

        // DefaultRequest.getHeaders() really returns a Map<String,String>, but for some reason it
        // comes back as a bare Map
        @SuppressWarnings("unchecked")
        private static Map<String, String> getHeadersMap(DefaultRequest request) {
            return request.getHeaders();
        }
    }
}
