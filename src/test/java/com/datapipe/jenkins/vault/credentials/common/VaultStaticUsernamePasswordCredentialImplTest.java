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
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.w3c.dom.Document;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

public class VaultStaticUsernamePasswordCredentialImplTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    /**
     * Verify that the transient {@code context} field is not serialized.
     */
    @Test
    public void itemGroupContextNotSerialized() throws Exception {
        ItemGroup ig = mock(ItemGroup.class);
        VaultStaticUsernamePasswordCredentialImpl cred =
            new VaultStaticUsernamePasswordCredentialImpl(
                CredentialsScope.GLOBAL, "foo", "foo credential");
        cred.setUsername("admin");
        cred.setContext(ig);

        File out = folder.newFile();
        new XmlFile(out).write(cred);

        try (FileInputStream fis = new FileInputStream(out)) {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(fis);
            XPath xpath = XPathFactory.newInstance().newXPath();
            String expression =
                "boolean(/com.datapipe.jenkins.vault.credentials.common"
                    + ".VaultStaticUsernamePasswordCredentialImpl/context/node())";
            assertEquals("false", xpath.compile(expression).evaluate(doc));
        }
    }

    /**
     * Verify that the plain-text {@code username} field is serialized and restored correctly.
     */
    @Test
    public void usernameSerialized() throws Exception {
        VaultStaticUsernamePasswordCredentialImpl cred =
            new VaultStaticUsernamePasswordCredentialImpl(
                CredentialsScope.GLOBAL, "bar", "bar credential");
        cred.setUsername("static-user");
        cred.setPasswordKey("secret");

        File out = folder.newFile();
        new XmlFile(out).write(cred);

        try (FileInputStream fis = new FileInputStream(out)) {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(fis);
            XPath xpath = XPathFactory.newInstance().newXPath();

            String usernameExpression =
                "string(/com.datapipe.jenkins.vault.credentials.common"
                    + ".VaultStaticUsernamePasswordCredentialImpl/username)";
            assertEquals("static-user", xpath.compile(usernameExpression).evaluate(doc));

            String passwordKeyExpression =
                "string(/com.datapipe.jenkins.vault.credentials.common"
                    + ".VaultStaticUsernamePasswordCredentialImpl/passwordKey)";
            assertEquals("secret", xpath.compile(passwordKeyExpression).evaluate(doc));
        }
    }

    /**
     * Verify default values: blank passwordKey defaults to "password", and username defaults to
     * empty string when null.
     */
    @Test
    public void defaultValues() {
        VaultStaticUsernamePasswordCredentialImpl cred =
            new VaultStaticUsernamePasswordCredentialImpl(
                CredentialsScope.GLOBAL, "baz", "baz credential");

        assertEquals("", cred.getUsername());

        cred.setPasswordKey(null);
        assertEquals(VaultStaticUsernamePasswordCredentialImpl.DEFAULT_PASSWORD_KEY,
            cred.getPasswordKey());
    }
}
