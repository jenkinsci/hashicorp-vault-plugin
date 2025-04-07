package com.datapipe.jenkins.vault.util;

import com.github.dockerjava.api.model.Capability;
import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.json.Json;
import io.github.jopenlibs.vault.json.JsonObject;
import java.io.File;
import java.io.IOException;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;

import static com.datapipe.jenkins.vault.util.TestConstants.CERT_PEMFILE;
import static com.datapipe.jenkins.vault.util.TestConstants.CONTAINER_CERT_PEMFILE;
import static com.datapipe.jenkins.vault.util.TestConstants.CONTAINER_CONFIG_FILE;
import static com.datapipe.jenkins.vault.util.TestConstants.CONTAINER_NETWORK;
import static com.datapipe.jenkins.vault.util.TestConstants.CONTAINER_OPENSSL_CONFIG_FILE;
import static com.datapipe.jenkins.vault.util.TestConstants.CONTAINER_SSL_DIRECTORY;
import static com.datapipe.jenkins.vault.util.TestConstants.CONTAINER_STARTUP_SCRIPT;
import static com.datapipe.jenkins.vault.util.TestConstants.DEFAULT_IMAGE_AND_TAG;
import static com.datapipe.jenkins.vault.util.TestConstants.MAX_RETRIES;
import static com.datapipe.jenkins.vault.util.TestConstants.RETRY_MILLIS;
import static com.datapipe.jenkins.vault.util.TestConstants.SSL_DIRECTORY;
import static com.datapipe.jenkins.vault.util.TestConstants.VAULT_PATH_KV1_1;
import static com.datapipe.jenkins.vault.util.VaultTestUtil.getTestPath;
import static com.datapipe.jenkins.vault.util.VaultTestUtil.hasDockerDaemon;
import static org.testcontainers.utility.MountableFile.forHostPath;

/**
 * Sets up and exposes utilities for dealing with a Docker-hosted instance of Vault, for integration tests.
 */
public class VaultContainer extends GenericContainer<VaultContainer> {

    private static final Logger LOGGER = LoggerFactory.getLogger(VaultContainer.class);

    private String rootToken;
    private String unsealKey;

    public VaultContainer() {
        super(DEFAULT_IMAGE_AND_TAG);
    }

    public static VaultContainer createVaultContainer() {
        if (!hasDockerDaemon()) {
            return null;
        }

        VaultContainer container = new VaultContainer()
            .withNetwork(CONTAINER_NETWORK)
            .withNetworkAliases("vault")
            .withCopyFileToContainer(forHostPath(
                getTestPath("vaultTest_server.hcl")),
                CONTAINER_CONFIG_FILE)
            .withCopyFileToContainer(forHostPath(
                getTestPath("startup.sh")),
                CONTAINER_STARTUP_SCRIPT)
            .withCopyFileToContainer(forHostPath(
                getTestPath("libressl.conf")),
                CONTAINER_OPENSSL_CONFIG_FILE)
            .withFileSystemBind(SSL_DIRECTORY, CONTAINER_SSL_DIRECTORY, BindMode.READ_WRITE)
            .withCreateContainerCmdModifier(command -> command.withCapAdd(Capability.IPC_LOCK))
            .withExposedPorts(8200)
            .withCommand("/bin/sh " + CONTAINER_STARTUP_SCRIPT)
            .withLogConsumer(new Slf4jLogConsumer(LOGGER))
            .waitingFor(Wait.forLogMessage(".+Vault server started!.+", 1));

        // Additionnal SAN can be set on the Vault Certificate. This allows Docker in Docker tests through TCP socket.
        container.withEnv("ADDITIONNAL_TEST_SAN", Optional.ofNullable(System.getenv("ADDITIONNAL_TEST_SAN")).orElse(""));

        // Propagate proxy settings for Docker in Docker tests
        if (System.getProperty("http.proxyHost") != null) {
            StringBuilder http_proxy = new StringBuilder();
            http_proxy.append("http://");
            if (System.getProperty("http.proxyUser") != null) {
                http_proxy.append(System.getProperty("http.proxyUser"))
                    .append(":")
                    .append(System.getProperty("http.proxyPassword"))
                    .append("@");
            }
            http_proxy.append(System.getProperty("http.proxyHost"));
            if (System.getProperty("http.proxyPort") != null) {
                http_proxy.append(":").append(System.getProperty("http.proxyPort"));
            }
            container.withEnv("http_proxy", http_proxy.toString());
        }
        if (System.getProperty("http.nonProxyHosts") != null) {
            container.withEnv("no_proxy", convertNonProxyHostsToNoProxy(System.getProperty("http.nonProxyHosts")));
        }
        if (System.getProperty("https.proxyHost") != null) {
            StringBuilder https_proxy = new StringBuilder();
            https_proxy.append("http://");
            if (System.getProperty("https.proxyUser") != null) {
                https_proxy.append(System.getProperty("https.proxyUser"))
                    .append(":")
                    .append(System.getProperty("https.proxyPassword"))
                    .append("@");
            }
            https_proxy.append(System.getProperty("https.proxyHost"));
            if (System.getProperty("https.proxyPort") != null) {
                https_proxy.append(":").append(System.getProperty("https.proxyPort"));
            }
            container.withEnv("https_proxy", https_proxy.toString());
        }
        if (System.getProperty("https.nonProxyHosts") != null) {
            container.withEnv("no_proxy", convertNonProxyHostsToNoProxy(System.getProperty("https.nonProxyHosts")));
        }

        // Override with environment proxy settings
        if (System.getenv("http_proxy") != null) {
            container.withEnv("http_proxy", System.getenv("http_proxy"));
        }
        if (System.getenv("HTTP_PROXY") != null) {
            container.withEnv("http_proxy", System.getenv("HTTP_PROXY"));
        }
        if (System.getenv("https_proxy") != null) {
            container.withEnv("https_proxy", System.getenv("https_proxy"));
        }
        if (System.getenv("HTTPS_PROXY") != null) {
            container.withEnv("https_proxy", System.getenv("HTTPS_PROXY"));
        }
        if (System.getenv("no_proxy") != null) {
            container.withEnv("no_proxy", System.getenv("no_proxy"));
        }
        if (System.getenv("NO_PROXY") != null) {
            container.withEnv("no_proxy", System.getenv("NO_PROXY"));
        }

        return container;
    }

    /**
     * Convert a Java NON_PROXY_HOSTS variable to a standard NO_PROXY one
     * @param noProxyHosts
     * @return
     */
    private static String convertNonProxyHostsToNoProxy(final String noProxyHosts) {
        return noProxyHosts.replaceAll("|", ",").replaceAll("\\*", "");
    }

    /**
     * To be called by a test class method annotated with {@link org.junit.jupiter.api.BeforeAll}.
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
        Vault vault = Vault.create(config);
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
        return Vault.create(config).withRetries(MAX_RETRIES, RETRY_MILLIS);
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
        return Vault.create(config).withRetries(MAX_RETRIES, RETRY_MILLIS);
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
        return String.format("https://%s:%d", getHost(), getMappedPort(8200));
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
