/*
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
package com.datapipe.jenkins.vault.model;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import com.datapipe.jenkins.vault.credentials.VaultCredential;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.util.ListBoxModel;
import java.util.List;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.verb.POST;

import static com.datapipe.jenkins.vault.configuration.VaultConfiguration.engineVersions;
import static hudson.Util.fixEmptyAndTrim;

/**
 * Represents a Vault secret.
 *
 * @author Peter Tierno {@literal <}ptierno{@literal @}datapipe.com{@literal >}
 */
public class VaultSecret extends AbstractDescribableImpl<VaultSecret> {

    private String path;
    private Integer engineVersion;
    private List<VaultSecretValue> secretValues;
    private String vaultCredentialId;
    private String vaultNamespace;

    @DataBoundConstructor
    public VaultSecret(String path, List<VaultSecretValue> secretValues) {
        this.path = fixEmptyAndTrim(path);
        this.secretValues = secretValues;
    }

    @DataBoundSetter
    public void setEngineVersion(Integer engineVersion) {
        this.engineVersion = engineVersion;
    }

    public String getPath() {
        return this.path;
    }

    public Integer getEngineVersion() {
        return this.engineVersion;
    }

    public List<VaultSecretValue> getSecretValues() {
        return this.secretValues;
    }

    @DataBoundSetter
    public void setVaultCredentialId(String vaultCredentialId) {
        this.vaultCredentialId = fixEmptyAndTrim(vaultCredentialId);
    }

    public String getVaultCredentialId() {
        return vaultCredentialId;
    }

    @DataBoundSetter
    public void setVaultNamespace(String vaultNamespace) {
        this.vaultNamespace = fixEmptyAndTrim(vaultNamespace);
    }

    public String getVaultNamespace() {
        return vaultNamespace;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<VaultSecret> {

        @Override
        public String getDisplayName() {
            return "Vault Secret";
        }

        @SuppressWarnings("unused") // used by stapler
        public ListBoxModel doFillEngineVersionItems(@AncestorInPath Item context) {
            return engineVersions(context);
        }

        @SuppressWarnings("unused") // used by stapler
        @POST
        public ListBoxModel doFillVaultCredentialIdItems(@AncestorInPath Item item,
            @org.kohsuke.stapler.QueryParameter String uri) {
            List<DomainRequirement> domainRequirements = URIRequirementBuilder.fromUri(uri).build();
            return new StandardListBoxModel().includeEmptyValue().includeAs(hudson.security.ACL.SYSTEM, item,
                VaultCredential.class, domainRequirements);
        }

    }

}
