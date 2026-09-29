package com.datapipe.jenkins.vault.credentials.common;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.UnbindableDir;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import static org.apache.commons.lang3.StringUtils.defaultIfBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

/**
 * Credential binding for {@link VaultPKICredentials} that exposes the issued certificate,
 * private key, and CA certificate as PEM files in the build workspace.
 *
 * <h2>Pipeline usage</h2>
 * <pre>{@code
 * withCredentials([vaultPKI(credentialsId: 'my-pki-cred',
 *                           certPemVariable: 'CERT_PEM',
 *                           privateKeyPemVariable: 'KEY_PEM',
 *                           caPemVariable: 'CA_PEM')]) {
 *     // Each variable holds a path to a temporary PEM file in the workspace.
 *     sh 'curl --cert $CERT_PEM --key $KEY_PEM --cacert $CA_PEM https://my-service'
 *     sh 'openssl verify -CAfile $CA_PEM $CERT_PEM'
 * }
 * }</pre>
 *
 * <p><strong>Security note:</strong> PEM files are written to a temporary directory that is
 * automatically deleted at the end of the {@code withCredentials} block.  The private key file
 * is created with {@code 0400} permissions (owner read-only) on POSIX systems.  Avoid printing
 * the contents of {@code $KEY_PEM} to the build log.</p>
 */
public class VaultPKICredentialsBinding extends MultiBinding<VaultPKICredentials> {

    public static final String DEFAULT_CERT_PEM_VARIABLE = "VAULT_PKI_CERT";
    public static final String DEFAULT_KEY_PEM_VARIABLE = "VAULT_PKI_KEY";
    public static final String DEFAULT_CA_PEM_VARIABLE = "VAULT_PKI_CA";

    private String certPemVariable;
    private String privateKeyPemVariable;
    private String caPemVariable;

    @DataBoundConstructor
    public VaultPKICredentialsBinding(String credentialsId) {
        super(credentialsId);
        this.certPemVariable = DEFAULT_CERT_PEM_VARIABLE;
        this.privateKeyPemVariable = DEFAULT_KEY_PEM_VARIABLE;
        this.caPemVariable = DEFAULT_CA_PEM_VARIABLE;
    }

    @DataBoundSetter
    public void setCertPemVariable(@Nullable String certPemVariable) {
        this.certPemVariable = defaultIfBlank(certPemVariable, DEFAULT_CERT_PEM_VARIABLE);
    }

    @DataBoundSetter
    public void setPrivateKeyPemVariable(@Nullable String privateKeyPemVariable) {
        this.privateKeyPemVariable = defaultIfBlank(privateKeyPemVariable, DEFAULT_KEY_PEM_VARIABLE);
    }

    @DataBoundSetter
    public void setCaPemVariable(@Nullable String caPemVariable) {
        this.caPemVariable = defaultIfBlank(caPemVariable, DEFAULT_CA_PEM_VARIABLE);
    }

    public String getCertPemVariable() {
        return certPemVariable;
    }

    public String getPrivateKeyPemVariable() {
        return privateKeyPemVariable;
    }

    public String getCaPemVariable() {
        return caPemVariable;
    }

    @Override
    protected Class<VaultPKICredentials> type() {
        return VaultPKICredentials.class;
    }

    /**
     * Issues the PKI certificate once and writes the PEM components to temporary files in the
     * workspace.  The {@link UnbindableDir} ensures the files are deleted when the
     * {@code withCredentials} block exits.
     */
    @Override
    public MultiEnvironment bind(@NonNull Run<?, ?> build, FilePath workspace, Launcher launcher,
        TaskListener listener) throws IOException, InterruptedException {

        VaultPKICredentials credentials = getCredentials(build);

        // Retrieve all PEM data in one shot – all three calls hit the same cached issuance
        String certPem = credentials.getCertificatePem();
        String keyPem = credentials.getPrivateKeyPem();
        String caPem = credentials.getIssuingCaPem();

        listener.getLogger().println("[VaultPKI] Writing PKI certificate PEM files to workspace");

        UnbindableDir tmpDir = UnbindableDir.create(workspace);

        Map<String, String> envMap = new HashMap<>();

        if (isNotBlank(certPemVariable)) {
            FilePath certFile = tmpDir.getDirPath().child("vault-pki-cert.pem");
            certFile.write(certPem, "UTF-8");
            envMap.put(certPemVariable, certFile.getRemote());
        }

        if (isNotBlank(privateKeyPemVariable)) {
            FilePath keyFile = tmpDir.getDirPath().child("vault-pki-key.pem");
            keyFile.write(keyPem, "UTF-8");
            // Restrict private key to owner read-only on POSIX systems
            try {
                keyFile.chmod(0400);
            } catch (Exception ignored) {
                // Windows or unsupported FS – best effort
            }
            envMap.put(privateKeyPemVariable, keyFile.getRemote());
        }

        if (isNotBlank(caPemVariable)) {
            FilePath caFile = tmpDir.getDirPath().child("vault-pki-ca.pem");
            caFile.write(caPem, "UTF-8");
            envMap.put(caPemVariable, caFile.getRemote());
        }

        return new MultiEnvironment(envMap, tmpDir.getUnbinder());
    }

    @Override
    public Set<String> variables() {
        Set<String> vars = new HashSet<>();
        if (isNotBlank(certPemVariable)) {
            vars.add(certPemVariable);
        }
        if (isNotBlank(privateKeyPemVariable)) {
            vars.add(privateKeyPemVariable);
        }
        if (isNotBlank(caPemVariable)) {
            vars.add(caPemVariable);
        }
        return vars;
    }

    @Symbol("vaultPKI")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<VaultPKICredentials> {

        @Override
        protected Class<VaultPKICredentials> type() {
            return VaultPKICredentials.class;
        }

        @Override
        public String getDisplayName() {
            return "Vault PKI Certificate (PEM files)";
        }

        public String getDefaultCertPemVariable() {
            return DEFAULT_CERT_PEM_VARIABLE;
        }

        public String getDefaultKeyPemVariable() {
            return DEFAULT_KEY_PEM_VARIABLE;
        }

        public String getDefaultCaPemVariable() {
            return DEFAULT_CA_PEM_VARIABLE;
        }
    }
}
