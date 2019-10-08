package com.datapipe.jenkins.vault.util;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.TestEnvironment;
import org.testcontainers.vault.VaultContainer;

import static com.github.dockerjava.api.model.Capability.IPC_LOCK;
import static org.apache.commons.io.FileUtils.writeStringToFile;
import static org.testcontainers.utility.MountableFile.forHostPath;

@SuppressWarnings("WeakerAccess")
public class VaultTestUtil implements TestConstants {

    private final static Logger LOGGER = Logger.getLogger(VaultTestUtil.class.getName());


    private static boolean configured = false;
    private static Network network = Network.newNetwork();

    public static void runCommand(VaultContainer container, final String... command)
        throws IOException, InterruptedException {
        LOGGER.log(Level.FINE, String.join(" ", command));
        container.execInContainer(command);
    }

    public static boolean hasDockerDaemon() {
        try {
            return TestEnvironment.dockerApiAtLeast("1.10");
        } catch (IllegalStateException e) {
            return false;
        }
    }

    public static VaultContainer createVaultContainer() {
        if (!hasDockerDaemon()) {
            return null;
        }
        return new VaultContainer<>(VaultTestUtil.VAULT_DOCKER_IMAGE)
            .withVaultToken(VaultTestUtil.VAULT_ROOT_TOKEN)
            .withNetwork(network)
            .withNetworkAliases("vault")
            .withCopyFileToContainer(forHostPath(
                TestConstants.class.getResource("vaultTest_adminPolicy.hcl").getPath()),
                "/admin.hcl")
            .withExposedPorts(8200)
            .waitingFor(Wait.forHttp("/v1/sys/seal-status").forStatusCode(200));
    }

    public static VaultContainer createVaultAgentContainer(
        Path roleIDPath,
        Path secretIDPath) {
        return new VaultContainer<>("vault:1.2.1")
            .withNetwork(network)
            .withCreateContainerCmdModifier(cmd -> cmd.withCapAdd(IPC_LOCK))
            .withCopyFileToContainer(forHostPath(
                TestConstants.class.getResource("vaultTest_agent.hcl").getPath()),
                "/agent.hcl")
            .withCopyFileToContainer(forHostPath(roleIDPath),
                "/home/vault/role_id")
            .withCopyFileToContainer(forHostPath(secretIDPath),
                "/home/vault/secret_id")
            .withCommand("vault agent -config=/agent.hcl -address=http://vault:8200")
            .withExposedPorts(8200)
            .waitingFor(Wait.forLogMessage(".*renewed auth token.*", 1));
    }

    public static String getAddress(VaultContainer container) {
        return String.format("http://%s:%d", container.getContainerIpAddress(), container.getMappedPort(8200));
    }

    public static void configureVaultContainer(VaultContainer container) {
        if (configured) {
            return;
        }
        try {
            // Create Secret Backends
            runCommand(container, "vault", "secrets", "enable", "-path=kv-v2",
                "-version=2", "kv");
            runCommand(container, "vault", "secrets", "enable", "-path=kv-v1",
                "-version=1", "kv");

            // Create user/password credential
            runCommand(container, "vault", "auth", "enable", "userpass");
            runCommand(container, "vault", "write", "auth/userpass/users/" + VAULT_USER,
                "password=" + VAULT_PW, "policies=admin");

            // Create policies
            runCommand(container, "vault", "policy", "write", "admin", "/admin.hcl");

            // Create AppRole
            runCommand(container, "vault", "auth", "enable", "approle");
            runCommand(container, "vault", "write", "auth/approle/role/admin",
                "secret_id_ttl=10m", "token_num_uses=0", "token_ttl=50ms", "token_max_ttl=50ms",
                "secret_id_num_uses=1000", "policies=admin");

            // Retrieve AppRole credentials
            VaultConfig config = new VaultConfig().address(getAddress(container))
                .token(VAULT_ROOT_TOKEN).engineVersion(1).build();
            Vault vaultClient = new Vault(config);
            final String roleID = vaultClient.logical().read("auth/approle/role/admin/role-id")
                .getData().get("role_id");
            final String secretID = vaultClient.logical().write("auth/approle/role/admin/secret-id",
                new HashMap<>()).getData().get("secret_id");

            Properties properties = new Properties();
            properties.put("CASC_VAULT_APPROLE", roleID);
            properties.put("CASC_VAULT_APPROLE_SECRET", secretID);

            Path filePath = Paths.get(System.getProperty("java.io.tmpdir"), VAULT_APPROLE_FILE);
            File file = filePath.toFile();
            FileOutputStream fos = new FileOutputStream(file);
            properties.store(fos, null);
            Path roleIDPath = Paths.get(System.getProperty("java.io.tmpdir"), "role_id");
            Path secretIDPath = Paths.get(System.getProperty("java.io.tmpdir"), "secret_id");
            writeStringToFile(roleIDPath.toFile(), roleID);
            writeStringToFile(secretIDPath.toFile(), secretID);

            // add secrets for v1 and v2
            runCommand(container, "vault", "kv", "put", VAULT_PATH_KV1_1, "key1=123",
                "key2=456");
            runCommand(container, "vault", "kv", "put", VAULT_PATH_KV1_2, "key3=789");
            runCommand(container, "vault", "kv", "put", VAULT_PATH_KV2_1, "key1=123",
                "key2=456");
            runCommand(container, "vault", "kv", "put", VAULT_PATH_KV2_2, "key3=789");
            runCommand(container, "vault", "kv", "put", VAULT_PATH_KV2_3, "key2=321");
            runCommand(container, "vault", "kv", "put", VAULT_PATH_KV2_AUTH_TEST,
                "key1=auth-test");
            VaultContainer vaultAgentContainer = createVaultAgentContainer(roleIDPath,
                secretIDPath);
            assert vaultAgentContainer != null;
            vaultAgentContainer.start();
            filePath = Paths.get(System.getProperty("java.io.tmpdir"), VAULT_AGENT_FILE);
            file = filePath.toFile();
            fos = new FileOutputStream(file);
            properties.clear();
            properties.put("CASC_VAULT_AGENT_ADDR", getAddress(vaultAgentContainer));
            properties.store(fos, null);
            LOGGER.log(Level.INFO, "Vault is configured");
            configured = true;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, e.getMessage());
        }
    }
}
