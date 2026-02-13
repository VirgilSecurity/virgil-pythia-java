/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.android.pythia;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.sdk.crypto.HashAlgorithm;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

import org.junit.Assume;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Base class for tests which uses environment-specific parameters.
 */
public class ConfigurableTest {

  private static final String ENVIRONMENT_SYS_VAR = "environment";
  private static final String DEFAULT_PYTHIA_SERVICE_URL = "https://api.virgilsecurity.com/pythia/v1";
  private static final String BASE_SERVICE_URL = "BASE_SERVICE_URL";
  private static final String APP_ID = "APP_ID";
  private static final String APP_KEY = "APP_KEY";

  private final Map<String, String> properties;
  private final VirgilCrypto crypto;
  private VirgilPrivateKey apiPrivateKey;

  public ConfigurableTest() {
    this.crypto = new VirgilCrypto();
    this.properties = Collections.unmodifiableMap(loadEnvJson(System.getProperty(ENVIRONMENT_SYS_VAR)));
  }

  private static Map<String, String> loadEnvJson(String environment) {
    InputStream stream = ConfigurableTest.class.getClassLoader()
        .getResourceAsStream("testProperties/env.json");
    if (stream == null) {
      return Collections.emptyMap();
    }

    try {
      String content = readAll(stream);
      JsonElement root = JsonParser.parseString(content);
      if (!root.isJsonObject()) {
        return Collections.emptyMap();
      }

      JsonObject obj = root.getAsJsonObject();
      if (!StringUtils.isBlank(environment) && obj.has(environment) && obj.get(environment).isJsonObject()) {
        obj = obj.getAsJsonObject(environment);
      }
      if (StringUtils.isBlank(environment) && !obj.has(APP_ID) && obj.entrySet().size() == 1) {
        Map.Entry<String, JsonElement> only = obj.entrySet().iterator().next();
        if (only.getValue() != null && only.getValue().isJsonObject()) {
          obj = only.getValue().getAsJsonObject();
        }
      }

      Map<String, String> out = new HashMap<>();
      for (Map.Entry<String, JsonElement> e : obj.entrySet()) {
        JsonElement v = e.getValue();
        if (v != null && v.isJsonPrimitive()) {
          out.put(e.getKey(), v.getAsString());
        }
      }
      return out;
    } catch (Exception ignored) {
      return Collections.emptyMap();
    }
  }

  private static String readAll(InputStream in) throws Exception {
    try (InputStream input = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      byte[] buf = new byte[4096];
      int n;
      while ((n = input.read(buf)) >= 0) {
        out.write(buf, 0, n);
      }
      return out.toString(StandardCharsets.UTF_8.name());
    }
  }

  private String getProperty(String key) {
    String v = properties.get(key);
    if (!StringUtils.isBlank(v)) {
      return v;
    }
    v = System.getProperty(key);
    if (!StringUtils.isBlank(v)) {
      return v;
    }
    v = System.getenv(key);
    return StringUtils.isBlank(v) ? null : v;
  }

  protected boolean isIntegrationConfigured() {
    return !StringUtils.isBlank(getAppId())
        && !StringUtils.isBlank(getApiPrivateKeyStr())
        && !StringUtils.isBlank(getApiPublicKeyId());
  }

  protected void assumeIntegrationConfigured() {
    Assume.assumeTrue("Integration test config is missing. Provide env.json to run.", isIntegrationConfigured());
    assumeServiceReachableForTests();
  }

  protected void assumeServiceReachableForTests() {
    String url = getPythiaServiceUrl();
    Assume.assumeTrue("No Pythia service URL configured", !StringUtils.isBlank(url));

    String host;
    try {
      host = URI.create(url).getHost();
    } catch (Exception e) {
      host = null;
    }
    Assume.assumeTrue("No service host extracted from url=" + url, !StringUtils.isBlank(host));

    try {
      InetAddress.getByName(host);
    } catch (Exception e) {
      Assume.assumeTrue("Unable to resolve host " + host + "; skipping integration tests", false);
    }
  }

  public String getPythiaServiceUrl() {
    String base = getProperty(BASE_SERVICE_URL);
    if (!StringUtils.isBlank(base)) {
      base = base.trim();
      while (base.endsWith("/")) {
        base = base.substring(0, base.length() - 1);
      }
      return base + "/pythia/v1";
    }

    return DEFAULT_PYTHIA_SERVICE_URL;
  }

  public String getAppId() {
    return getProperty(APP_ID);
  }

  public String getApiPrivateKeyStr() {
    return getProperty(APP_KEY);
  }

  public VirgilPrivateKey getApiPrivateKey() {
    if (this.apiPrivateKey == null) {
      try {
        this.apiPrivateKey = this.crypto
            .importPrivateKey(ConvertionUtils.base64ToBytes(getApiPrivateKeyStr()))
            .getPrivateKey();
      } catch (CryptoException e) {
        fail("API Private Key has invalid format");
      }
    }
    return this.apiPrivateKey;
  }

  public String getApiPublicKeyId() {
    return derivePublicKeyIdFromPrivateKey(getApiPrivateKeyStr());
  }

  private String derivePublicKeyIdFromPrivateKey(String privateKeyValue) {
    if (StringUtils.isBlank(privateKeyValue)) {
      return null;
    }
    try {
      VirgilKeyPair keyPair = this.crypto.importPrivateKey(ConvertionUtils.base64ToBytes(privateKeyValue));
      byte[] publicKeyBytes = this.crypto.exportPublicKey(keyPair.getPublicKey());
      byte[] publicKeyBase64Bytes = ConvertionUtils.toBase64Bytes(publicKeyBytes);
      byte[] publicKeyHash = this.crypto.computeHash(publicKeyBase64Bytes, HashAlgorithm.SHA512);
      return ConvertionUtils.toHex(publicKeyHash).substring(0, 32).toLowerCase();
    } catch (Exception ignored) {
      return null;
    }
  }

  public void assertNotEmpty(String arrayDescription, byte[] array) {
    assertNotNull(String.format("%s should not be null", arrayDescription), array);
    assertTrue(String.format("%s should not be empty", arrayDescription), array.length > 0);
  }
}
