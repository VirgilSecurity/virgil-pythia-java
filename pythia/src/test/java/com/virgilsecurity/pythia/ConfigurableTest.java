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

package com.virgilsecurity.pythia;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.HashAlgorithm;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

import org.junit.jupiter.api.Assumptions;

import java.io.File;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Base class for tests which uses environment-specific parameters.
 * 
 * @author Andrii Iakovenko
 *
 */
public class ConfigurableTest {

  private static final String ENVIRONMENT_SYS_VAR = "environment";
  private static final String DEFAULT_PYTHIA_SERVICE_URL = "https://api.virgilsecurity.com/pythia/v1";
  private static final String BASE_SERVICE_URL = "BASE_SERVICE_URL";
  private static final String APP_ID = "APP_ID";
  private static final String APP_KEY = "APP_KEY";
  private final Map<String, String> properties;

  private VirgilCrypto crypto;
  private VirgilPrivateKey apiPrivateKey;

  /**
   * Create a new instance of {@link ConfigurableTest}.
   */
  public ConfigurableTest() {
    String environment = System.getProperty(ENVIRONMENT_SYS_VAR);
    this.properties = Collections.unmodifiableMap(loadEnvJson(environment));
    this.crypto = new VirgilCrypto();
  }

  private static Map<String, String> loadEnvJson(String environment) {
    File envJson = new File("env.json");
    if (!envJson.exists()) {
      return Collections.emptyMap();
    }

    try {
      String content = new String(Files.readAllBytes(envJson.toPath()), StandardCharsets.UTF_8);
      JsonElement root = JsonParser.parseString(content);
      if (!root.isJsonObject()) {
        return Collections.emptyMap();
      }

      JsonObject obj = root.getAsJsonObject();
      // Support env.json shapes like:
      // 1) { "APP_ID": "...", ... }
      // 2) { "dev": { "APP_ID": "...", ... }, "prod": { ... } } with -Denvironment=dev
      if (!StringUtils.isBlank(environment) && obj.has(environment) && obj.get(environment).isJsonObject()) {
        obj = obj.getAsJsonObject(environment);
      }
      // 3) { "pro": { ... } } with no -Denvironment set (common when only one environment exists)
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

  protected boolean isIntegrationConfigured() {
    return !StringUtils.isBlank(getAppId())
        && !StringUtils.isBlank(getApiPrivateKeyStr())
        && !StringUtils.isBlank(getApiPublicKeyId());
  }

  protected void assumeIntegrationConfigured() {
    Assumptions.assumeTrue(isIntegrationConfigured(),
        "Integration test config is missing. Provide env.json (or set APP_* env vars) to run.");
    assumeServiceReachableForTests();
  }

  protected void assumeServiceReachableForTests() {
    String url = getPythiaServiceUrl();
    Assumptions.assumeTrue(!StringUtils.isBlank(url), "No Pythia service URL configured");

    String host;
    try {
      host = URI.create(url).getHost();
    } catch (Exception e) {
      host = null;
    }
    Assumptions.assumeTrue(!StringUtils.isBlank(host), "No service host extracted from url=" + url);

    try {
      InetAddress.getByName(host);
    } catch (Exception e) {
      Assumptions.assumeTrue(false, "Unable to resolve host " + host + "; skipping integration tests");
    }
  }

  private String getProperty(String key) {
    String v = this.properties.get(key);
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

  /**
   * Get Pythia service base URL.
   *
   * @return Pythia service base URL.
   */
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

  /**
   * Get the application identifier.
   *
   * @return the application identifier.
   */
  public String getAppId() {
    return getProperty(APP_ID);
  }

  /**
   * Get API Private Key as Base64-encoded string.
   *
   * @return API Private Key as Base64-encoded string.
   */
  public String getApiPrivateKeyStr() {
    return getProperty(APP_KEY);
  }

  /**
   * Get API Private Key.
   *
   * @return API Private Key.
   */
  public VirgilPrivateKey getApiPrivateKey() {
    if (this.apiPrivateKey == null) {
      try {
        this.apiPrivateKey = this.crypto
            .importPrivateKey(ConvertionUtils.base64ToBytes(getApiPrivateKeyStr())).getPrivateKey();
      } catch (CryptoException e) {
        fail("API Private Key has invalid format");
      }
    }
    return this.apiPrivateKey;
  }

  /**
   * Get API Private Key identifier.
   *
   * @return API Private Key identifier.
   */
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

  /**
   * Assert that array is not null and not empty.
   *
   * @param arrayDescription
   *          the short array description.
   * @param array
   *          the array to be verified.
   */
  public void assertNotEmpty(String arrayDescription, byte[] array) {
    assertNotNull(array, String.format("%s should not be null", arrayDescription));
    assertTrue(array.length > 0, String.format("%s should not be empty", arrayDescription));
  }

}
