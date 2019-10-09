package com.datapipe.jenkins.vault.it.buildwrapper;

import com.datapipe.jenkins.vault.util.VaultContainer;
import java.io.IOException;

public class AbstractSSLTest {

    public static VaultContainer container = new VaultContainer();

    static {
        container.start();
        try {
            container.initAndUnsealVault();
            container.setBasicSecrets();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
