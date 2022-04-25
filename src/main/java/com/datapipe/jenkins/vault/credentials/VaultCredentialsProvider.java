package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.properties.FolderCredentialsProvider.FolderCredentialsProperty;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.datapipe.jenkins.vault.credentials.common.AbstractVaultBaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.acegisecurity.Authentication;

/**
 * This class provides the credentials that we need to authenticate against Vault
 * and the credentials stored in Vault, after assigning the right context to them.
 *
 * @author Hassan CHAKROUN {@literal <h.chakrouun@gmail.com> }
 *
 */
@Extension(optional = true, ordinal = 1)
public class VaultCredentialsProvider extends CredentialsProvider {

    @Override
    public <C extends Credentials> List<C> getCredentials(Class<C> type, ItemGroup itemGroup, Authentication authentication) {
        return getCredentials(type, itemGroup, authentication, Collections.emptyList());
    }

    @NonNull
    @Override
    public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> type,
                                                          @Nullable ItemGroup itemGroup,
                                                          @Nullable Authentication authentication,
                                                          @NonNull List<DomainRequirement> domainRequirements) {
        CredentialsMatcher matcher = (type != VaultCredential.class ?
                                        CredentialsMatchers.instanceOf(AbstractVaultBaseStandardCredentials.class) :
                                        CredentialsMatchers.always());
        List<C> creds = new ArrayList<C>();
        if (ACL.SYSTEM.equals(authentication)) {
            for (ItemGroup g = itemGroup; g instanceof AbstractFolder; g = (AbstractFolder.class.cast(g)).getParent()) {
                FolderCredentialsProperty property = ((AbstractFolder<?>) g).getProperties()
                                                                           .get(FolderCredentialsProperty.class);
                if (property == null) {
                    continue;
                }

                List<C> folderCreds = DomainCredentials.getCredentials(
                                                    property.getDomainCredentialsMap(),
                                                    type,
                                                    domainRequirements,
                                                    matcher
                                                );
                creds.addAll(folderCreds);
            }

            List<C> globalCreds = DomainCredentials.getCredentials(
                                                SystemCredentialsProvider.getInstance().getDomainCredentialsMap(),
                                                type,
                                                domainRequirements,
                                                matcher
                                            );
            creds.addAll(globalCreds);
        }

        return creds;
    }
}
