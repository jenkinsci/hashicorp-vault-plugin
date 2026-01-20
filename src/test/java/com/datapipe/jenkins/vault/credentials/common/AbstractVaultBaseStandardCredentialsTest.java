package com.datapipe.jenkins.vault.credentials.common;

import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.XmlFile;
import hudson.model.ItemGroup;
import java.io.File;
import java.io.FileInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.jvnet.hudson.test.Issue;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class AbstractVaultBaseStandardCredentialsTest {

    @TempDir
    private File folder;

    /**
     * Verify {@link AbstractVaultBaseStandardCredentials} does not attempt to serialize ItemGroup
     * context.
     */
    @Test
    @Issue("https://github.com/jenkinsci/hashicorp-vault-plugin/issues/264")
    void itemGroupContextNotSerialized() throws Exception {
        ItemGroup ig = mock(ItemGroup.class);
        VaultUsernamePasswordCredentialImpl cred = new VaultUsernamePasswordCredentialImpl(
            CredentialsScope.GLOBAL, "foo", "foo credential");
        cred.setContext(ig);

        // serialize object using xstream
        File out = File.createTempFile("junit", null, folder);
        new XmlFile(out).write(cred);

        // verify document does not include include context field
        try (FileInputStream fis = new FileInputStream(out)) {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(fis);
            XPath xpath = XPathFactory.newInstance().newXPath();
            String expression = "boolean(/com.datapipe.jenkins.vault.credentials.common.VaultUsernamePasswordCredentialImpl/context/node())";
            assertEquals("false", xpath.compile(expression).evaluate(doc));
        }
    }
}
