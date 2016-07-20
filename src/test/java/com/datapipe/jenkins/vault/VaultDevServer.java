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

import java.io.IOException;

/**
 * 
 * @author Peter Tierno {@literal <}ptierno{@literal @}datapipe.com{@literal >}
 */
public class VaultDevServer {

  Process vaultProcess;
  String rootToken;

  public VaultDevServer(String rootToken) {
    this.rootToken = rootToken;
  }

  public Process getVaultProcess() {
    return this.vaultProcess;
  }

  public String getRootToken() {
    return this.rootToken;
  }

  public void startServer() throws IOException {
    Process p = Runtime.getRuntime()
        .exec("/usr/local/bin/vault server -dev -dev-root-token-id="
            + this.rootToken);
    this.vaultProcess = p;
  }

  public void stopServer() {
    this.vaultProcess.destroy();
    this.vaultProcess = null;
  }

}
