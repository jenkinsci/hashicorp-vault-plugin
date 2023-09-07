package com.datapipe.jenkins.vault.jcasc.secrets;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import hudson.Extension;
import io.jenkins.plugins.casc.SecretSource;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang.StringUtils;

/**
 * Requires either CASC_VAULT_USER and CASC_VAULT_PW, or CASC_VAULT_TOKEN, or CASC_VAULT_APPROLE and
 * CASC_VAULT_APPROLE_SECRET, or CASC_VAULT_KUBERNETES_ROLE, or CASC_VAULT_AWS_IAM_ROLE environment
 * variables set alongside with CASC_VAULT_PATHS and CASC_VAULT_URL
 */
@Extension(optional = true)
public class VaultSecretSource extends SecretSource {

    private final static Logger LOGGER = Logger.getLogger(VaultSecretSource.class.getName());

    private static final String CASC_VAULT_FILE = "CASC_VAULT_FILE";
    private static final String CASC_VAULT_PW = "CASC_VAULT_PW";
    private static final String CASC_VAULT_USER = "CASC_VAULT_USER";
    private static final String CASC_VAULT_URL = "CASC_VAULT_URL";
    private static final String CASC_VAULT_AGENT_ADDR = "CASC_VAULT_AGENT_ADDR";
    private static final String CASC_VAULT_MOUNT = "CASC_VAULT_MOUNT";
    private static final String CASC_VAULT_TOKEN = "CASC_VAULT_TOKEN";
    private static final String CASC_VAULT_APPROLE = "CASC_VAULT_APPROLE";
    private static final String CASC_VAULT_APPROLE_SECRET = "CASC_VAULT_APPROLE_SECRET";
    private static final String CASC_VAULT_KUBERNETES_ROLE = "CASC_VAULT_KUBERNETES_ROLE";
    private static final String CASC_VAULT_AWS_IAM_ROLE = "CASC_VAULT_AWS_IAM_ROLE";
    private static final String CASC_VAULT_AWS_TARGET_IAM_ROLE = "CASC_VAULT_AWS_TARGET_IAM_ROLE";
    private static final String CASC_VAULT_AWS_IAM_SERVER_ID = "CASC_VAULT_AWS_IAM_SERVER_ID";
    private static final String CASC_VAULT_NAMESPACE = "CASC_VAULT_NAMESPACE";
    private static final String CASC_VAULT_PREFIX_PATH = "CASC_VAULT_PREFIX_PATH";
    private static final String CASC_VAULT_ENGINE_VERSION = "CASC_VAULT_ENGINE_VERSION";
    private static final String CASC_VAULT_PATHS = "CASC_VAULT_PATHS";
    private static final String CASC_VAULT_PATH = "CASC_VAULT_PATH"; // TODO: deprecate!
    private static final String DEFAULT_ENGINE_VERSION = "2";
    private static final String DEFAULT_USER_BACKEND = "userpass";
    private static final String DEFAULT_APPROLE_BACKEND = "approle";
    private static final String DEFAULT_KUBERNETES_BACKEND = "kubernetes";
    private static final String DEFAULT_AWS_IAM_BACKEND = "aws";

    private Map<String, String> secrets = new HashMap<>();
    private Vault vault;
    private VaultConfig vaultConfig;
    private VaultAuthenticator vaultAuthenticator;
    private String[] vaultPaths;
    private Properties prop;
    private boolean usingVaultAgent;

    private void configureVault() {
        // Read config file/env
        prop = new Properties();
        Optional<String> vaultFile = Optional.ofNullable(System.getenv(CASC_VAULT_FILE));
        vaultFile.ifPresent(this::readPropertiesFromVaultFile);

        // Parse variables
        Optional<String> vaultEngineVersionOpt = getVariable(CASC_VAULT_ENGINE_VERSION);
        Optional<String> vaultUrl = getVariable(CASC_VAULT_AGENT_ADDR)
            .map(Optional::of)
            .orElseGet(() -> getVariable(CASC_VAULT_URL));
        Optional<String> vaultNamespace = getVariable(CASC_VAULT_NAMESPACE);
        Optional<String> vaultPrefixPath = getVariable(CASC_VAULT_PREFIX_PATH);
        Optional<String[]> vaultPaths = getCommaSeparatedVariables(CASC_VAULT_PATHS);
        getVariable(CASC_VAULT_PATH).ifPresent(s -> LOGGER
            .log(Level.SEVERE, "{0} is deprecated, please switch to {1}",
                new Object[]{CASC_VAULT_PATH, CASC_VAULT_PATHS}));

        // Check mandatory variables are set
        if (!vaultUrl.isPresent() || !vaultPaths.isPresent()) return;

        if (getVariable(CASC_VAULT_AGENT_ADDR).isPresent()) usingVaultAgent = true;

        String vaultEngineVersion = vaultEngineVersionOpt.orElse(DEFAULT_ENGINE_VERSION);
        this.vaultPaths = vaultPaths.get();
        determineAuthenticator();

        // configure vault client
        vaultConfig = new VaultConfig().address(vaultUrl.get());
        try {
            LOGGER.log(Level.FINE, "Attempting to connect to Vault: {0}", vaultUrl);
            if (vaultNamespace.isPresent()) {
                vaultConfig.nameSpace(vaultNamespace.get());
                LOGGER.log(Level.FINE, "Using namespace with Vault: {0}", vaultNamespace);
            }

            vaultConfig.engineVersion(Integer.parseInt(vaultEngineVersion));
            LOGGER.log(Level.FINE, "Using engine version: {0}", vaultEngineVersion);

            if (vaultPrefixPath.isPresent()) {
                vaultConfig.prefixPath(vaultPrefixPath.get());
                LOGGER.log(Level.FINE, "Using prefixPath with Vault: {0}", vaultPrefixPath);
            }
        } catch (VaultException e) {
            LOGGER.log(Level.WARNING, "Could not configure vault connection", e);
        }

        try {
            vaultConfig.build();
        } catch (VaultException e) {
            LOGGER.log(Level.WARNING, "Could not configure vault client", e);
        }

        vault = new Vault(vaultConfig);
    }

    private void determineAuthenticator() {
        Optional<String> vaultPw = getVariable(CASC_VAULT_PW);
        Optional<String> vaultUser = getVariable(CASC_VAULT_USER);
        Optional<String> vaultToken = getVariable(CASC_VAULT_TOKEN);
        Optional<String> vaultAppRole = getVariable(CASC_VAULT_APPROLE);
        Optional<String> vaultAppRoleSecret = getVariable(CASC_VAULT_APPROLE_SECRET);
        Optional<String> vaultKubernetesRole = getVariable(CASC_VAULT_KUBERNETES_ROLE);
        Optional<String> vaultAwsIamRole = getVariable(CASC_VAULT_AWS_IAM_ROLE);

        vaultToken.ifPresent(this::token);
        allPresent(vaultUser, vaultPw, this::userPass);
        allPresent(vaultAppRole, vaultAppRoleSecret, this::approle);
        vaultKubernetesRole.ifPresent(this::kubernetes);
        vaultAwsIamRole.ifPresent(this::awsIam);

        if (vaultAuthenticator == null && !usingVaultAgent) {
            LOGGER.log(Level.WARNING, "Could not determine vault authentication method. Not able to read secrets from vault.");
        }
    }

    private void setAuthenticator(VaultAuthenticator vaultAuthenticator) {
        // Overwrite current authenticator only if there was a change, because we do not want to loose current auth token
        if (vaultAuthenticator != null
            && !vaultAuthenticator.equals(this.vaultAuthenticator)) {
            this.vaultAuthenticator = vaultAuthenticator;
        }
    }

    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    public static <T, U> void allPresent(Optional<T> o1, Optional<U> o2, BiConsumer<T, U> consumer) {
        o1.ifPresent(t -> o2.ifPresent(u -> consumer.accept(t, u)));
    }

    private void token(String token) {
        setAuthenticator(VaultAuthenticator.of(token));
    }

    private void userPass(String user, String pass) {
        Optional<String> mount = getVariable(CASC_VAULT_MOUNT);
        setAuthenticator(VaultAuthenticator
            .of(new VaultUsernamePassword(user, pass), mount.orElse(DEFAULT_USER_BACKEND)));
    }

    private void approle(String approle, String approleSecret) {
        Optional<String> mount = getVariable(CASC_VAULT_MOUNT);
        setAuthenticator(VaultAuthenticator
            .of(new VaultAppRole(approle, approleSecret), mount.orElse(DEFAULT_APPROLE_BACKEND)));
    }

    private void kubernetes(String role) {
        Optional<String> mount = getVariable(CASC_VAULT_MOUNT);
        setAuthenticator(VaultAuthenticator
            .of(new VaultKubernetes(role), mount.orElse(DEFAULT_KUBERNETES_BACKEND)));
    }

    private void awsIam(String role) {
        Optional<String> serverId = getVariable(CASC_VAULT_AWS_IAM_SERVER_ID);
        Optional<String> targetIamRole = getVariable(CASC_VAULT_AWS_TARGET_IAM_ROLE);
        Optional<String> mount = getVariable(CASC_VAULT_MOUNT);
        setAuthenticator(VaultAuthenticator
            .of(new VaultAwsIam(role, targetIamRole.orElse(""), serverId.orElse("")), mount.orElse(DEFAULT_AWS_IAM_BACKEND)));
    }

    private void readSecretsFromVault() {
        Optional<String[]> vaultPathsOpt = Optional.ofNullable(vaultPaths);

        if (vaultPathsOpt.isPresent()) {
            try {
                // refresh map
                secrets = new HashMap<>();

                // Parse secrets
                for (String vaultPath : vaultPathsOpt.get()) {
                    Map<String, String> nextSecrets = vault.logical().read(vaultPath).getData();
                    Map<String, String> nextSecretsFullPath = new HashMap<String, String>();
                    // create item where key is full path to secret
                    for (Map.Entry<String, String> secretEntry : nextSecrets.entrySet()) {
                        nextSecretsFullPath.put(vaultPath + "/" + secretEntry.getKey(), secretEntry.getValue());
                    }
                    // check if we overwrite an existing key from another path
                    // TODO(casz) handle error response
                    for (String key : nextSecrets.keySet()) {
                        if (secrets.containsKey(key)) {
                            LOGGER.log(Level.FINE, "Key {0} exists in multiple vault paths. Use full path ({1}) to access value.",
                                    new Object[]{key, vaultPath + "/" + key});
                        }
                    }

                    // merge
                    secrets.putAll(nextSecrets);
                    secrets.putAll(nextSecretsFullPath);
                }
            } catch (VaultException e) {
                LOGGER.log(Level.WARNING, "Unable to fetch secret from Vault", e);
            }
        }
    }

    private void readPropertiesFromVaultFile(String vaultFile) {
        try (FileInputStream input = new FileInputStream(vaultFile)) {
            prop.load(input);
            if (prop.isEmpty()) {
                LOGGER.log(Level.WARNING, "Vault secret file is empty");
            }
        } catch (IOException ex) {
            LOGGER.log(Level.WARNING, "Failed to load Vault secrets from file", ex);
        }
    }

    @Override
    public Optional<String> reveal(String secret) {
        if (StringUtils.isBlank(secret)) return Optional.empty();
        return Optional.ofNullable(secrets.get(secret));
    }

    public Map<String, String> getSecrets() {
        return secrets;
    }

    public void setSecrets(Map<String, String> secrets) {
        this.secrets = secrets;
    }

    private Optional<String> getVariable(String key) {
        return Optional.ofNullable(prop.getProperty(key, System.getenv(key)));
    }

    private Optional<String[]> getCommaSeparatedVariables(String key) {
        return getVariable(key).map(str -> str.split(","));
    }

    @Override
    public void init() {
        configureVault();

        // Ensure secrets are up-to-date and Check vault authentication
        if (vaultAuthenticator != null) {
            try {
                vaultAuthenticator.authenticate(vault, vaultConfig);
            } catch (VaultException e) {
                LOGGER.log(Level.WARNING, "Could not authenticate with vault client", e);
            }
        }
        if (vaultAuthenticator != null || usingVaultAgent) {
            readSecretsFromVault();
        }
    }
}
