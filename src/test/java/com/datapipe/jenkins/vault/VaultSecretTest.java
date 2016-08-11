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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;

public class VaultSecretTest {

  private static VaultSecret secret;
  private static List<VaultSecretValue> values;

  /**
   * Setup our SUT before any tests are run
   * 
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    VaultSecretTest.values = new ArrayList<VaultSecretValue>();
    VaultSecretTest.values.add(new VaultSecretValue("envVar", "vaultKey"));
    VaultSecretTest.secret = new VaultSecret("path", VaultSecretTest.values); // SUT
  }

  /**
   * Test method for
   * {@link com.datapipe.jenkins.vault.VaultSecret#VaultSecret(java.lang.String, java.lang.String, java.lang.String)}
   * .
   */
  @Test
  public void testConstructor() {
    assertEquals("path", VaultSecretTest.secret.getPath());
    VaultSecretValue value = VaultSecretTest.secret.getSecretValues().get(0);
    assertEquals("envVar", value.getEnvVar());
    assertEquals("vaultKey", value.getVaultKey());
    assertThat(VaultSecretTest.values,
        is(VaultSecretTest.secret.getSecretValues()));
  }

  /**
   * Test method for {@link com.datapipe.jenkins.vault.VaultSecret#getPath()}.
   */
  @Test
  public void testGetPath() {
    assertEquals("path", VaultSecretTest.secret.getPath());
  }

  /**
   * Test method for {@link com.datapipe.jenkins.vault.VaultSecret#getSecret()}.
   */
  @Test
  public void testGetSecretValues() {
    assertThat(VaultSecretTest.values,
        is(VaultSecretTest.secret.getSecretValues()));
  }
}
