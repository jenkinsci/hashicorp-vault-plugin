/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Datapipe, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.datapipe.jenkins.vault;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.AbstractIdCredentialsListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.matchers.IdMatcher;
import com.datapipe.jenkins.vault.credentials.VaultTokenCredential;
import hudson.*;
import hudson.console.ConsoleLogFilter;
import hudson.model.*;
import hudson.security.ACL;
import hudson.tasks.BuildWrapper;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildWrapper;
import net.sf.json.JSONNull;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Sample {@link BuildWrapper}.
 *
 * <p>
 * When the user configures the project and enables this builder,
 * {@link DescriptorImpl#newInstance(StaplerRequest)} is invoked and a new {@link VaultBuildWrapper}
 * is created. The created instance is persisted to the project configuration XML by using XStream,
 * so this allows you to use instance fields (like {@link #vaultUrl}) to remember the configuration.
 * </p>
 *
 * <p>
 * When a build is performed, the {@link #preCheckout(AbstractBuild, Launcher, BuildListener)}
 * method will be invoked.
 * </p>
 *
 * @author Peter Tierno {@literal <}ptierno{@literal @}datapipe.com{@literal >}
 */
public class VaultBuildWrapper extends SimpleBuildWrapper {

  private String vaultUrl;
  private String authTokenCredentialId;
  private List<VaultSecret> vaultSecrets;
  private List<String> valuesToMask = new ArrayList<>();

  // Possibly add these later
  // private final int openTimeout;
  // private final int readTimeout;

  // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
  @DataBoundConstructor
  public VaultBuildWrapper(@CheckForNull List<VaultSecret> vaultSecrets) {
    this.vaultSecrets = vaultSecrets;

    // Defaults to null to allow using global configuration
    // I am not sure this is necessary.
    this.vaultUrl = null;
    this.authTokenCredentialId = null;
  }

  @DataBoundSetter
  public void setVaultUrl(String vaultUrl) {
    this.vaultUrl = vaultUrl;
  }

  public String getVaultUrl() {
    return this.vaultUrl;
  }

  @DataBoundSetter
  public void setAuthTokenCredentialId(String authTokenCredentialId) {
    this.authTokenCredentialId = authTokenCredentialId;
  }

  public String getAuthTokenCredentialId() {
    return this.authTokenCredentialId;
  }

  public List<VaultSecret> getVaultSecrets() {
    return this.vaultSecrets;
  }

  private String getUrl() {
    if (this.vaultUrl == null || this.vaultUrl.isEmpty()) {
      return getDescriptor().getVaultUrl();
    }
    return this.vaultUrl;
  }

  private String getToken() {
    String id = authTokenCredentialId;
    if (id == null || id.isEmpty()) {
      id = getDescriptor().getAuthTokenCredentialId();
    }
    List<VaultTokenCredential> credentials = CredentialsProvider.lookupCredentials(VaultTokenCredential.class, Jenkins.getInstance(), ACL.SYSTEM, Collections.<DomainRequirement>emptyList());
    VaultTokenCredential credential = CredentialsMatchers.firstOrNull(credentials, new IdMatcher(id));
    return credential == null ? null : Secret.toString(credential.getToken());
  }

  // Overridden for better type safety.
  // If your plugin doesn't really define any property on Descriptor
  // you don't have to do this.
  @Override
  public DescriptorImpl getDescriptor() {
    return (DescriptorImpl) super.getDescriptor();
  }

  @Override
  public void setUp(Context context, Run<?, ?> build, FilePath workspace,
      Launcher launcher, TaskListener listener, EnvVars initialEnvironment)
      throws IOException, InterruptedException {
    // This is where you 'build' the project.
    PrintStream logger = listener.getLogger();

    String url = getUrl();
    String token = getToken();

    for (VaultSecret vaultSecret : vaultSecrets) {

      try {
        VaultConfig vaultConfig = new VaultConfig(url, token).build();

        Vault vault = new Vault(vaultConfig);

        Map<String, String> values =
            vault.logical().read(vaultSecret.getPath()).getData();

        for (VaultSecretValue value : vaultSecret.getSecretValues()) {
          valuesToMask.add(values.get(value.getVaultKey()));
          context.env(value.getEnvVar(), values.get(value.getVaultKey()));
        }

      } catch (VaultException e) {
        e.printStackTrace(logger);
        throw new AbortException(e.getMessage());
      }
    }
  }

  @Override
  public ConsoleLogFilter createLoggerDecorator(
      @Nonnull final Run<?, ?> build) {
    return new MaskingConsoleLogFilter(build.getCharset().name(), valuesToMask);
  }

  /**
   * Descriptor for {@link VaultBuildWrapper}. Used as a singleton. The class is marked as public so
   * that it can be accessed from views.
   * 
   * <p>
   * See <tt>src/main/resources/com/datapipe/jenkins/vault/VaultBuildWrapper/*.jelly</tt> for the
   * actual HTML fragment for the configuration screen.
   */
  @Extension // This indicates to Jenkins that this is an implementation of an extension point.
  public static final class DescriptorImpl extends Descriptor<BuildWrapper> {

    /**
     * To persist global configuration information, simply store it in a field and call save().
     * 
     * <p>
     * If you don't want fields to be persisted, use <tt>transient</tt>.
     */
    private String vaultUrl;

    private String authTokenCredentialId;

    /**
     * In order to load the persisted global configuration, you have to call load() in the
     * constructor.
     */
    public DescriptorImpl() {
      super(VaultBuildWrapper.class);
      load();
    }

    public boolean isApplicable(AbstractProject<?, ?> item) {
      // Indicates that this builder can be used with all kinds of project types
      return true;
    }

    /**
     * This human readable name is used in the configuration screen.
     */
    @Override
    public String getDisplayName() {
      return "Vault Plugin";
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject formData)
        throws FormException {
      // To persist global configuration information,
      // set that to properties and call save().
      Object vaultUrl = formData.getString("vaultUrl");
      Object authTokenCredentialId = formData.getString("authTokenCredentialId");

      if (!JSONNull.getInstance().equals(vaultUrl)) {
        this.vaultUrl = (String) vaultUrl;
      } else {
        this.vaultUrl = null;
      }

      if (!JSONNull.getInstance().equals(authTokenCredentialId)) {
        this.authTokenCredentialId = (String) authTokenCredentialId;
      } else {
        this.authTokenCredentialId = null;
      }

      save();
      return super.configure(req, formData);
    }

    public String getVaultUrl() {
      return this.vaultUrl;
    }

    // Required by external plugins (according to Articfactory plugin)
    public void setVaultUrl(String vaultUrl) {
      this.vaultUrl = vaultUrl;
    }

    public String getAuthTokenCredentialId() {
      return authTokenCredentialId;
    }

    public void setAuthTokenCredentialId(String authTokenCredentialId) {
      this.authTokenCredentialId = authTokenCredentialId;
    }

    public ListBoxModel doFillAuthTokenCredentialIdItems(){
      if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
        return new ListBoxModel();
      }
      AbstractIdCredentialsListBoxModel model = new StandardListBoxModel().includeEmptyValue().includeAs(ACL.SYSTEM, Jenkins.getInstance(), VaultTokenCredential.class);
      return model;
    }
  }

}
