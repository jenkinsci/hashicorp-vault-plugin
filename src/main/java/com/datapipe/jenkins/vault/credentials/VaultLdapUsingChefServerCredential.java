package com.datapipe.jenkins.vault.credentials;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.datapipe.jenkins.vault.exception.VaultPluginException;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import hudson.Extension;
import org.jclouds.ContextBuilder;
import org.jclouds.chef.ChefApi;
import org.jclouds.chef.ChefApiMetadata;
import org.jclouds.chef.domain.DatabagItem;
import org.kohsuke.stapler.DataBoundConstructor;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Stream;

public class VaultLdapUsingChefServerCredential extends BaseStandardCredentials implements VaultCredential {

    private final @Nonnull
    String serviceAccountName;
    private final @Nonnull
    String nodeName;
    private final @Nonnull
    String clientPemFilePath;
    private final @Nonnull
    String chefServerUrl;
    private final @Nonnull
    String chefOrg;
    private final @Nonnull
    String dataBag;
    private final @Nonnull
    String dataBagItem;
    private final @Nonnull
    String dataBagItemKey;

    @DataBoundConstructor
    public VaultLdapUsingChefServerCredential(@CheckForNull CredentialsScope scope, @CheckForNull String id, @CheckForNull String description, @Nonnull String serviceAccountName, @Nonnull String nodeName, @Nonnull String clientPemFilePath, @Nonnull String chefServerUrl, @Nonnull String chefOrg, @Nonnull String dataBag, @Nonnull String dataBagItem, @Nonnull String dataBagItemKey) {
        super(scope, id, description);
        this.serviceAccountName = serviceAccountName;
        this.nodeName = nodeName;
        this.clientPemFilePath = clientPemFilePath;
        this.chefServerUrl = chefServerUrl;
        this.chefOrg = chefOrg;
        this.dataBag = dataBag;
        this.dataBagItem = dataBagItem;
        this.dataBagItemKey = dataBagItemKey;
    }

    @Override
    public Vault authorizeWithVault(Vault vault, VaultConfig config) {
        String token = null;
        try {
            // Read the client.pem for a node
            String clientPem = this.readFile(clientPemFilePath).trim().toString();
            // Build a chefApi context
            ContextBuilder contextBuilder = ContextBuilder.newBuilder(new ChefApiMetadata())
                        .endpoint(chefServerUrl+"/oraganizations/"+chefOrg)
                        .credentials(nodeName, clientPem);
            ChefApi chefApi = contextBuilder.buildApi(ChefApi.class);
            // Fetch data bag that contains the credentials (Like service acoount password)
            DatabagItem item = chefApi.getDatabagItem(dataBag, dataBagItem);
            chefApi.close();

            JsonElement parsedJson = new JsonParser().parse(item.toString());
            String serviceAccountPassword = parsedJson.getAsJsonObject().get(dataBagItemKey).getAsString();
            // Use service account and it's password for Auth.
            token = vault.auth().loginByLDAP(serviceAccountName, serviceAccountPassword).getAuthClientToken();
        } catch (VaultException e) {
            throw new VaultPluginException("Couldn't login into vault", e);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new Vault(config.token(token));
    }

    public String readFile(String filePath) {
        StringBuffer contentBuilder = new StringBuffer();
        try (Stream<String> stream = Files.lines(Paths.get(clientPemFilePath), StandardCharsets.UTF_8)) {
            stream.forEach(line -> contentBuilder.append(line).append("\n"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return contentBuilder.toString();
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {

        @Override public String getDisplayName() {
            return "Vault LDAP Credential using Chef server";
        }

    }
}

