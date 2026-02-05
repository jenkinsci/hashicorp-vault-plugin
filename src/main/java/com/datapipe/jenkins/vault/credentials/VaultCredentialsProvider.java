package com.datapipe.jenkins.vault.credentials;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.properties.FolderCredentialsProvider.FolderCredentialsProperty;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.datapipe.jenkins.vault.credentials.common.AbstractVaultBaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import jenkins.model.Jenkins;
import org.springframework.security.core.Authentication;

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
    @NonNull
    public <C extends Credentials> List<C> getCredentialsInItemGroup(@NonNull Class<C> type,
        @Nullable ItemGroup itemGroup,
        @Nullable Authentication authentication,
        @NonNull List<DomainRequirement> domainRequirements) {
        CredentialsMatcher matcher = (type != VaultCredential.class ?
            CredentialsMatchers.instanceOf(AbstractVaultBaseStandardCredentials.class) :
            CredentialsMatchers.always());
        List<C> creds = new ArrayList<>();
        if (ACL.SYSTEM2.equals(authentication)) {
            for (ItemGroup<?> g = itemGroup; g instanceof AbstractFolder; g = ((AbstractFolder<?>) g).getParent()) {
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

                if (type != VaultCredential.class) {
                    for (C c : folderCreds) {
                        ((AbstractVaultBaseStandardCredentials) c).setContext(g);
                    }
                }

                creds.addAll(folderCreds);
            }

            // Only include SYSTEM-scoped credentials when context is Jenkins (global).
            // This prevents exposure of SYSTEM-scoped credentials to item/folder contexts (CVE-2025-67642).
            boolean includeSystemCredentials = itemGroup instanceof Jenkins;
            List<C> globalCreds = DomainCredentials.getCredentials(
                SystemCredentialsProvider.getInstance().getDomainCredentialsMap(),
                type,
                domainRequirements,
                matcher
            );

            for (C c : globalCreds) {
                if (!includeSystemCredentials && CredentialsScope.SYSTEM == c.getScope()) {
                    continue;
                }
                if (type != VaultCredential.class) {
                    ((AbstractVaultBaseStandardCredentials) c).setContext(Jenkins.get());
                }
                creds.add(c);
            }
        }
        return creds;
    }

    @Override
    @NonNull
    public <C extends Credentials> List<C> getCredentialsInItem(@NonNull Class<C> type,
        @NonNull Item item,
        @Nullable Authentication authentication,
        @NonNull List<DomainRequirement> domainRequirements) {
        // Scoping to Items is not supported so using null when parent is Jenkins
        // to not expose SYSTEM credentials to Items (CVE-2025-67642).
        Objects.requireNonNull(item);
        ItemGroup<?> parent = item.getParent();
        ItemGroup<?> context = (parent instanceof Jenkins) ? null : parent;
        return getCredentialsInItemGroup(type, context, authentication, domainRequirements);
    }
}
