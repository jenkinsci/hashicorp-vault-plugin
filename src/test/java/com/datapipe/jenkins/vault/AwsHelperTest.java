package com.datapipe.jenkins.vault;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Auth;
import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.json.JsonArray;
import com.bettercloud.vault.json.JsonObject;
import com.bettercloud.vault.response.AuthResponse;
import com.datapipe.jenkins.vault.AwsHelper;
import hudson.Util;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

public class AwsHelperTest {

    private static final String awsAccessKey = "ASIAIOSFODNN7EXAMPLE";
    private static final String awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String sessionToken = "sometoken";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testGetTokenBasicDefaults() throws VaultException {
        BasicAWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        doTestGetToken(credentials, "", "", "");
    }

    @Test
    public void testGetTokenBasicCustom() throws VaultException {
        BasicAWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        doTestGetToken(credentials, "somerole", "someserverid", "somemount");
    }

    @Test
    public void testGetTokenSessionDefaults() throws VaultException {
        BasicSessionCredentials credentials = new BasicSessionCredentials(awsAccessKey, awsSecretKey, sessionToken);
        doTestGetToken(credentials, "", "", "");
    }

    @Test
    public void testGetTokenSessionCustom() throws VaultException {
        BasicSessionCredentials credentials = new BasicSessionCredentials(awsAccessKey, awsSecretKey, sessionToken);
        doTestGetToken(credentials, "somerole", "someserverid", "somemount");
    }

    private static void doTestGetToken(AWSCredentials credentials, String role, String serverId, String mount) throws VaultException {
        final Auth auth = mock(Auth.class);
        final AuthResponse resp = mock(AuthResponse.class);
        when(auth.loginByAwsIam(any(), anyString(), anyString(), anyString(), any()))
            .thenReturn(resp);
        when(resp.getAuthClientToken()).thenReturn("mocktoken");

        final String vaultToken = AwsHelper.getToken(auth, credentials, role, null, serverId, mount);
        assertThat(vaultToken, is("mocktoken"));

        final ArgumentCaptor<String> roleArg = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<String> urlArg = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<String> bodyArg = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<String> headersArg = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<String> mountArg = ArgumentCaptor.forClass(String.class);
        verify(auth).loginByAwsIam(roleArg.capture(), urlArg.capture(), bodyArg.capture(), headersArg.capture(), mountArg.capture());

        assertThat(roleArg.getValue(), is(Util.fixEmptyAndTrim(role)));
        assertThat(mountArg.getValue(), is(Util.fixEmptyAndTrim(mount)));

        final Charset charset = StandardCharsets.UTF_8;
        final Base64.Decoder decoder = Base64.getDecoder();

        final String decodedUrl = new String(decoder.decode(urlArg.getValue()), charset);
        assertThat(decodedUrl, is("https://sts.amazonaws.com/"));

        final String decodedBody = new String(decoder.decode(bodyArg.getValue()), charset);
        assertThat(decodedBody, is("Action=GetCallerIdentity&Version=2011-06-15"));

        final String decodedHeaders = new String(decoder.decode(headersArg.getValue()), charset);
        final JsonObject headersObject = Json.parse(decodedHeaders).asObject();

        final List<String> expectedHeaderNames = new ArrayList<String>();
        expectedHeaderNames.add("Host");
        expectedHeaderNames.add("Content-Type");
        expectedHeaderNames.add("Authorization");
        expectedHeaderNames.add("X-Amz-Date");
        if (credentials instanceof AWSSessionCredentials) {
            expectedHeaderNames.add("X-Amz-Security-Token");
        }
        if (StringUtils.isNotEmpty(serverId)) {
            expectedHeaderNames.add("X-Vault-AWS-IAM-Server-ID");
        }
        assertThat(headersObject.names(), containsInAnyOrder(expectedHeaderNames.toArray()));

        final Map headersMap = new HashMap<String, String>();
        for (JsonObject.Member member : headersObject) {
            final JsonArray valuesArray = member.getValue().asArray();
            assertThat(valuesArray.size(), is(1));
            headersMap.put(member.getName(), valuesArray.get(0).asString());
        }
        assertThat(headersMap.get("Host"), is("sts.amazonaws.com"));
        assertThat(headersMap.get("Content-Type"), is("application/x-www-form-urlencoded; charset=utf-8"));
        if (credentials instanceof AWSSessionCredentials) {
            final AWSSessionCredentials sessionCreds = (AWSSessionCredentials) credentials;
            assertThat(headersMap.get("X-Amz-Security-Token"), is(sessionCreds.getSessionToken()));
        }
        if (StringUtils.isNotEmpty(serverId)) {
            assertThat(headersMap.get("X-Vault-AWS-IAM-Server-ID"), is(serverId));
        }
    }

}
