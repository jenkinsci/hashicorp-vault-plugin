package com.datapipe.jenkins.vault.util;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.json.JsonObject;
import com.github.dockerjava.api.model.Capability;
import java.io.File;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.lifecycle.TestDescription;
import org.testcontainers.lifecycle.TestLifecycleAware;

import static com.datapipe.jenkins.vault.util.VaultTestUtil.hasDockerDaemon;
import static org.junit.Assume.assumeTrue;
import static org.testcontainers.utility.MountableFile.forHostPath;

/**
 * Sets up and exposes utilities for dealing with a Docker-hosted instance of Vault, for integration tests.
 */
public class VaultContainer extends GenericContainer<VaultContainer> implements TestConstants {

    private static final Logger LOGGER = LoggerFactory.getLogger(VaultContainer.class);

    public static final String DEFAULT_IMAGE_AND_TAG = "vault:1.1.3";

    private String rootToken;
    private String unsealKey;

    public VaultContainer() {
        super(DEFAULT_IMAGE_AND_TAG);
    }

    public static VaultContainer createVaultContainer() {
        if (!hasDockerDaemon()) {
            return null;
        }
        return new VaultContainer()
            .withNetwork(CONTAINER_NETWORK)
            .withNetworkAliases("vault")
            .withCopyFileToContainer(forHostPath(
                TestConstants.class.getResource("vaultTest_server.hcl").getPath()),
                CONTAINER_CONFIG_FILE)
            .withCopyFileToContainer(forHostPath(
                TestConstants.class.getResource("startup.sh").getPath()),
                CONTAINER_STARTUP_SCRIPT)
            .withCopyFileToContainer(forHostPath(
                TestConstants.class.getResource("libressl.conf").getPath()),
                CONTAINER_OPENSSL_CONFIG_FILE)
            .withFileSystemBind(SSL_DIRECTORY, CONTAINER_SSL_DIRECTORY, BindMode.READ_WRITE)
            .withCreateContainerCmdModifier(command -> command.withCapAdd(Capability.IPC_LOCK))
            .withExposedPorts(8200)
            .withCommand("/bin/sh " + CONTAINER_STARTUP_SCRIPT)
            .withLogConsumer(new Slf4jLogConsumer(LOGGER))
            .waitingFor(Wait.forLogMessage(".+Vault server started!.+", 1));
    }

    /**
     * To be called by a test class method annotated with {@link org.junit.BeforeClass}.
     * This logic doesn't work when placed inside of the constructor, presumably
     * because the Docker container spawned by TestContainers is not ready to accept commands until after those
     * methods complete.
     *
     * <p>This method initializes the Vault server, capturing the unseal key and root token that are displayed on the
     * console.  It then uses the key to unseal the Vault instance, and stores the token in a member field so it
     * will be available to other methods.</p>
     *
     * @throws IOException
     * @throws InterruptedException
     */
    public void initAndUnsealVault() throws IOException, InterruptedException {


        // Initialize the Vault server
        final Container.ExecResult initResult = runCommand("vault", "operator", "init", "-ca-cert=" +
            CONTAINER_CERT_PEMFILE, "-key-shares=1", "-key-threshold=1", "-format=json");
        final String stdout = initResult.getStdout().replaceAll("\\r?\\n", "");
        JsonObject initJson = Json.parse(stdout).asObject();
        this.unsealKey = initJson.get("unseal_keys_b64").asArray().get(0).asString();
        this.rootToken = initJson.get("root_token").asString();

        System.out.println("Root token: " + rootToken);

        // Unseal the Vault server
        runCommand("vault", "operator", "unseal", "-tls-skip-verify", unsealKey);
        runCommand("vault", "login", "-tls-skip-verify", rootToken);
    }

    public void setBasicSecrets() throws IOException, InterruptedException {
        runCommand("vault", "secrets", "enable", "-tls-skip-verify", "-path=kv-v1", "-version=1", "kv");
        runCommand("vault", "kv", "put", "-tls-skip-verify", VAULT_PATH_KV1_1, "key1=123", "key2=456");
    }

    public void setEngineVersions() throws IOException, InterruptedException {
        // Upgrade default secrets/ Engine to V2, set a new V1 secrets path at "kv-v1/"
        runCommand("vault", "kv", "enable-versioning", "-tls-skip-verify", "secret/");
        runCommand("vault", "secrets", "enable", "-tls-skip-verify", "-path=secret", "-version=2", "kv");
        runCommand("vault", "secrets", "enable", "-tls-skip-verify", "-path=kv-v1", "-version=1", "kv");
        runCommand("vault", "secrets", "enable", "-tls-skip-verify", "-path=kv-v1-Upgrade-Test", "-version=1", "kv");
    }

    /**
     * <p>Constructs an instance of the Vault driver, providing maximum flexibility to control all options
     * explicitly.</p>
     *
     * <p>If <code>maxRetries</code> and <code>retryMillis</code> are BOTH null, then the <code>Vault</code>
     * instance will be constructed with retry logic disabled.  If one OR the other are null, the the class-level
     * default value will be used in place of the missing one.</p>
     *
     * @param config
     * @param maxRetries
     * @param retryMillis
     * @return
     */
    public Vault getVault(final VaultConfig config, final Integer maxRetries, final Integer retryMillis) {
        Vault vault = new Vault(config);
        if (maxRetries != null && retryMillis != null) {
            vault = vault.withRetries(maxRetries, retryMillis);
        } else if (maxRetries != null) {
            vault = vault.withRetries(maxRetries, RETRY_MILLIS);
        } else if (retryMillis != null) {
            vault = vault.withRetries(MAX_RETRIES, retryMillis);
        }
        return vault;
    }

    /**
     * Constructs an instance of the Vault driver, using sensible defaults.
     *
     * @return
     * @throws VaultException
     */
    public Vault getVault() throws VaultException {
        final VaultConfig config =
            new VaultConfig()
                .address(getAddress())
                .openTimeout(5)
                .readTimeout(30)
                .sslConfig(new SslConfig().pemFile(new File(CERT_PEMFILE)).build())
                .build();
        return getVault(config, MAX_RETRIES, RETRY_MILLIS);
    }

    /**
     * Constructs a VaultConfig that can be used to configure your own tests
     *
     * @return
     * @throws VaultException
     */

    public VaultConfig getVaultConfig() throws VaultException {
        return new VaultConfig()
            .address(getAddress())
            .openTimeout(5)
            .readTimeout(30)
            .sslConfig(new SslConfig().pemFile(new File(CERT_PEMFILE)).build())
            .build();
    }

    /**
     * Constructs an instance of the Vault driver with sensible defaults, configured to use the supplied token
     * for authentication.
     *
     * @param token
     * @return
     * @throws VaultException
     */
    public Vault getVault(final String token) throws VaultException {
        final VaultConfig config =
            new VaultConfig()
                .address(getAddress())
                .token(token)
                .openTimeout(5)
                .readTimeout(30)
                .sslConfig(new SslConfig().pemFile(new File(CERT_PEMFILE)).build())
                .build();
        return new Vault(config).withRetries(MAX_RETRIES, RETRY_MILLIS);
    }

    /**
     * Constructs an instance of the Vault driver using a custom Vault config.
     *
     * @return
     * @throws VaultException
     */
    public Vault getRootVaultWithCustomVaultConfig(VaultConfig vaultConfig) throws VaultException {
        final VaultConfig config =
            vaultConfig
                .address(getAddress())
                .token(rootToken)
                .openTimeout(5)
                .readTimeout(30)
                .sslConfig(new SslConfig().pemFile(new File(CERT_PEMFILE)).build())
                .build();
        return new Vault(config).withRetries(MAX_RETRIES, RETRY_MILLIS);
    }

    /**
     * Constructs an instance of the Vault driver with sensible defaults, configured to the use the root token
     * for authentication.
     *
     * @return
     * @throws VaultException
     */
    public Vault getRootVault() throws VaultException {
        return getVault(rootToken).withRetries(MAX_RETRIES, RETRY_MILLIS);
    }

    /**
     * The Docker container uses bridged networking.  Meaning that Vault listens on port 8200 inside the container,
     * but the tests running on the host machine cannot reach that port directly.  Instead, the Vault connection
     * config has to use a port that is mapped to the container's port 8200.  There is no telling what the mapped
     * port will be until runtime, so this method is necessary to build a Vault connection URL with the appropriate
     * values.
     *
     * @return The URL of the Vault instance
     */
    public String getAddress() {
        return String.format("https://%s:%d", getContainerIpAddress(), getMappedPort(8200));
    }

    /**
     * Returns the master key for unsealing the Vault instance.  This method should really ONLY be used by tests
     * specifically for sealing and unsealing functionality (i.e. SealTests.java).  Generally, tests should
     * retrieve Vault instances from the "getVault(...)" or "getRootVault()" methods here, and never directly
     * concern themselves with the root token or unseal key at all.
     *
     * @return The master key for unsealing this Vault instance
     */
    public String getUnsealKey() {
        return unsealKey;
    }

    public String getRootToken() {
        return rootToken;
    }

    /**
     * Runs the specified command from within the Docker container.
     *
     * @param command The command to run, broken up by whitespace
     *                (e.g. "vault mount -path=pki pki" becomes "vault", "mount", "-path=pki", "pki")
     * @return
     * @throws IOException
     * @throws InterruptedException
     */
    private Container.ExecResult runCommand(final String... command) throws IOException, InterruptedException {
        LOGGER.info("Command: {}", String.join(" ", command));
        final Container.ExecResult result = execInContainer(command);
        final String out = result.getStdout();
        final String err = result.getStderr();
        if (out != null && !out.isEmpty()) {
            LOGGER.info("Command stdout: {}", result.getStdout());
        }
        if (err != null && !err.isEmpty()) {
            LOGGER.info("Command stderr: {}", result.getStderr());
        }
        return result;
    }
}
