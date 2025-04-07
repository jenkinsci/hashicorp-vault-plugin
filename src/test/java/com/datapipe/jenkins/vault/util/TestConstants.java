package com.datapipe.jenkins.vault.util;

import java.io.File;
import org.testcontainers.containers.Network;

public interface TestConstants {

    String DEFAULT_IMAGE_AND_TAG = "vault:1.1.3";

    Integer TIMEOUT = 2;
    String JENKINSFILE_URL = "http://jenkinsfile-vault-url.com";

    String GLOBAL_CREDENTIALS_ID_1 = "global-1";
    String GLOBAL_CREDENTIALS_ID_2 = "global-2";
    Integer GLOBAL_ENGINE_VERSION_2 = 2;

    String APP_ID = "fake_app";
    String USER_ID = "fake_user";
    String PASSWORD = "fake_password";
    int MAX_RETRIES = 5;
    int RETRY_MILLIS = 1000;

    String CURRENT_WORKING_DIRECTORY = System.getProperty("user.dir") + "/src/test/resources/com/datapipe/jenkins/vault/util";
    String SSL_DIRECTORY = CURRENT_WORKING_DIRECTORY + File.separator + "ssl";
    String CERT_PEMFILE = SSL_DIRECTORY + File.separator + "root-cert.pem";

    String CONTAINER_STARTUP_SCRIPT = "/vault/config/startup.sh";
    String CONTAINER_CONFIG_FILE = "/vault/config/config.hcl";
    String CONTAINER_OPENSSL_CONFIG_FILE = "/vault/config/libressl.conf";
    String CONTAINER_SSL_DIRECTORY = "/vault/config/ssl";
    String CONTAINER_CERT_PEMFILE = CONTAINER_SSL_DIRECTORY + "/vault-cert.pem";
    String CONTAINER_CLIENT_CERT_PEMFILE = CONTAINER_SSL_DIRECTORY + "/client-cert.pem";

    String AGENT_CONFIG_FILE = "/home/vault/agent.hcl";
    String APPROLE_POLICY_FILE = "/home/vault/approlePolicy.hcl";

    Network CONTAINER_NETWORK = Network.newNetwork();

    String VAULT_DOCKER_IMAGE = "vault:1.0.3";
    String VAULT_ROOT_TOKEN = "root-token";
    String VAULT_USER = "admin";
    String VAULT_PW = "admin";
    String VAULT_PATH_KV1_1 = "kv-v1/admin";
    String VAULT_PATH_KV1_2 = "kv-v1/dev";
    String VAULT_PATH_KV2_1 = "kv-v2/admin";
    String VAULT_PATH_KV2_2 = "kv-v2/dev";
    String VAULT_PATH_KV2_3 = "kv-v2/qa";
    String VAULT_PATH_KV2_AUTH_TEST = "kv-v2/auth-test";
    String VAULT_PATH_LONG_KV2_1 = "long/path/kv-v2/admin";
    String VAULT_PATH_LONG_KV2_2 = "long/path/kv-v2/dev";
    String VAULT_PATH_LONG_KV2_PREFIX_PATH = "long/path/kv-v2";
    String VAULT_APPROLE_FILE = "JCasC_temp_approle_secret.prop";
    String VAULT_AGENT_FILE = "JCasC_temp_vault_agent.prop";
}
