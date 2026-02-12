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

import com.virgilsecurity.crypto.foundation.Base64;
import com.virgilsecurity.crypto.pythia.Pythia;
import com.virgilsecurity.crypto.pythia.PythiaComputeTransformationKeyPairResult;
import com.virgilsecurity.crypto.pythia.PythiaTransformResult;
import com.virgilsecurity.pythia.brainkey.BrainKey;
import com.virgilsecurity.pythia.brainkey.BrainKeyContext;
import com.virgilsecurity.pythia.client.PythiaClient;
import com.virgilsecurity.pythia.client.VirgilPythiaClient;
import com.virgilsecurity.pythia.crypto.PythiaCrypto;
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto;
import com.virgilsecurity.pythia.model.TransformResponse;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.StringUtils;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

/**
 * Integration test for {@link BrainKey}.
 * 
 * @author Andrii Iakovenko
 *
 */
public class BrainKeyTest extends ConfigurableTest {
  private static final String TEXT = "Lorem Ipsum is simply dummy text";

  private VirgilCrypto virgilCrypto;
  private PythiaCrypto pythiaCrypto;
  private PythiaClient pythiaClient;
  private BrainKey brainKey;
  private String identity;

  private SampleDataHolder sample;

  @Before
  public void setup() throws IOException {
    assumeIntegrationConfigured();

    this.virgilCrypto = new VirgilCrypto();
    this.pythiaCrypto = new VirgilPythiaCrypto();

    String baseUrl = getPythiaServiceUrl();
    if (StringUtils.isBlank(baseUrl)) {
      this.pythiaClient = new VirgilPythiaClient();
    } else {
      this.pythiaClient = new VirgilPythiaClient(baseUrl);
    }

    this.identity = "pythia_user_" + UUID.randomUUID().toString();

    JwtGenerator generator = new JwtGenerator(getAppId(), getApiPrivateKey(), getApiPublicKeyId(),
        TimeSpan.fromTime(1, TimeUnit.HOURS), new VirgilAccessTokenSigner());
    AccessTokenProvider accessTokenProvider = new GeneratorJwtProvider(generator, identity);

    BrainKeyContext context = new BrainKeyContext.Builder()
        .setAccessTokenProvider(accessTokenProvider).setPythiaCrypto(pythiaCrypto)
        .setPythiaClient(pythiaClient).build();
    this.brainKey = new BrainKey(context);

    sample = new SampleDataHolder("brainkey.json");
  }

  @Test
  public void generateKeyPair_noBrainKeyId() throws CryptoException, VirgilPythiaServiceException {
    VirgilKeyPair keyPair = this.brainKey.generateKeyPair("some password");
    assertNotNull(keyPair);

    byte[] data = TEXT.getBytes();
    byte[] encryptedText = this.virgilCrypto.encrypt(data, keyPair.getPublicKey());
    byte[] decryptedText = this.virgilCrypto.decrypt(encryptedText, keyPair.getPrivateKey());

    assertArrayEquals(data, decryptedText);
  }

  @Test
  public void generateKeyPair_multipleKeys()
      throws CryptoException, VirgilPythiaServiceException, InterruptedException {
    // YTC-22
    VirgilKeyPair keyPair1 = this.brainKey.generateKeyPair(sample.get("kPassword1"));

    Thread.sleep(2000);
    VirgilKeyPair keyPair2 = this.brainKey.generateKeyPair(sample.get("kPassword1"));
    assertArrayEquals(keyPair1.getPrivateKey().getIdentifier(),
        keyPair2.getPrivateKey().getIdentifier());

    Thread.sleep(2000);
    VirgilKeyPair keyPair3 = this.brainKey.generateKeyPair(sample.get("kPassword2"));
    assertFalse(Arrays.equals(keyPair1.getPrivateKey().getIdentifier(),
        keyPair3.getPrivateKey().getIdentifier()));

    Thread.sleep(2000);
    VirgilKeyPair keyPair4 = this.brainKey.generateKeyPair(sample.get("kPassword1"),
        sample.get("kBrainKeyId"));
    assertFalse(Arrays.equals(keyPair1.getPrivateKey().getIdentifier(),
        keyPair4.getPrivateKey().getIdentifier()));
  }

  @Test
  public void generateKeyPair_fakeClient() throws VirgilPythiaServiceException, CryptoException {
    // YTC-21
    PythiaClient mockedClient = new PythiaClient() {

      @Override
      public TransformResponse transformPassword(byte[] salt, byte[] blindedPassword,
          Integer version, boolean includeProof, String token) throws VirgilPythiaServiceException {
        return null;
      }

      @Override
      public byte[] generateSeed(byte[] blindedPassword, String brainKeyId, String token)
          throws VirgilPythiaServiceException {
        byte[] transformationKeyId = sample.getBytes("kTransformationKeyId");
        byte[] pythiaSecret = sample.getBytes("kSecret");
        byte[] pythiaScopeSecret = sample.getBytes("kScopeSecret");
        byte[] tweek = ("userId" + (brainKeyId == null ? "" : brainKeyId))
            .getBytes(StandardCharsets.UTF_8);

        PythiaComputeTransformationKeyPairResult transformationKeyPair = Pythia
            .computeTransformationKeyPair(transformationKeyId, pythiaSecret, pythiaScopeSecret);
        PythiaTransformResult transformResult = Pythia.transform(blindedPassword, tweek,
            transformationKeyPair.getTransformationPrivateKey());

        return transformResult.getTransformedPassword();
      }
    };

    JwtGenerator generator = new JwtGenerator(getAppId(), getApiPrivateKey(), getApiPublicKeyId(),
        TimeSpan.fromTime(1, TimeUnit.HOURS), new VirgilAccessTokenSigner());
    AccessTokenProvider accessTokenProvider = new GeneratorJwtProvider(generator, identity);
    BrainKeyContext context = new BrainKeyContext.Builder()
        .setAccessTokenProvider(accessTokenProvider).setPythiaCrypto(pythiaCrypto)
        .setPythiaClient(mockedClient).build();
    BrainKey mockedBrainKey = new BrainKey(context);

    VirgilKeyPair keyPair1 = mockedBrainKey.generateKeyPair(sample.get("kPassword1"));
    assertArrayEquals(Base64.decode(sample.get("kKeyId1").getBytes()),
                      keyPair1.getPrivateKey().getIdentifier());

    VirgilKeyPair keyPair2 = mockedBrainKey.generateKeyPair(sample.get("kPassword1"));
    assertArrayEquals(Base64.decode(sample.get("kKeyId1").getBytes()),
        keyPair2.getPrivateKey().getIdentifier());

    VirgilKeyPair keyPair3 = mockedBrainKey.generateKeyPair(sample.get("kPassword2"));
    assertArrayEquals(Base64.decode(sample.get("kKeyId2").getBytes()),
        keyPair3.getPrivateKey().getIdentifier());

    VirgilKeyPair keyPair4 = mockedBrainKey.generateKeyPair(sample.get("kPassword1"),
        sample.get("kBrainKeyId"));
    assertArrayEquals(Base64.decode(sample.get("kKeyId3").getBytes()),
        keyPair4.getPrivateKey().getIdentifier());
  }

}
