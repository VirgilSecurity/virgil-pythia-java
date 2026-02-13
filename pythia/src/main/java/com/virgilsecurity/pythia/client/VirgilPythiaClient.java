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

package com.virgilsecurity.pythia.client;

import com.virgilsecurity.common.util.Validator;
import com.virgilsecurity.pythia.model.GenerateSeedResponse;
import com.virgilsecurity.pythia.model.TransformResponse;
import com.virgilsecurity.pythia.model.exception.ThrottlingException;
import com.virgilsecurity.pythia.model.exception.VirgilPythiaServiceException;
import com.virgilsecurity.pythia.model.request.GenerateSeedRequest;
import com.virgilsecurity.pythia.model.request.TransformPasswordRequest;
import com.virgilsecurity.pythia.VirgilInfo;
import com.virgilsecurity.sdk.common.ErrorResponse;
import com.virgilsecurity.sdk.common.HttpError;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.OsUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * {@link PythiaClient} implementation.
 * 
 * @author Andrii Iakovenko
 *
 */
public final class VirgilPythiaClient implements PythiaClient {

  private static final Logger LOGGER = Logger.getLogger(VirgilPythiaClient.class.getName());
  // Pythia service base URL. Accepts both:
  // - https://api.virgilsecurity.com
  // - https://api.virgilsecurity.com/pythia/v1
  // All request paths are built as absolute (/pythia/v1/...) to avoid URL resolution pitfalls.
  private static final String BASE_URL = "https://api.virgilsecurity.com/pythia/v1";
  private static final String VIRGIL_AGENT_HEADER = "virgil-agent";

  private String bppVirgilAgent;
  private String brainkeyVirgilAgent;
  private URL baseUrl;

  /**
   * Create a new instance of {@link VirgilPythiaClient}.
   *
   */
  public VirgilPythiaClient() {
    this(BASE_URL);
  }

  /**
   * Create a new instance of {@link VirgilPythiaClient}.
   *
   * @param baseUrl the service url to fire requests to.
   */
  public VirgilPythiaClient(String baseUrl) {
    this(baseUrl, "bpp", "brainkey", VirgilInfo.VERSION);
  }

  /**
   * Create a new instance of {@link VirgilPythiaClient}.
   *
   * @param bppProduct      bpp Virgil Agent token.
   * @param brainkeyProduct brainkey Virgil agent token.
   * @param version         library version.
   */
  public VirgilPythiaClient(String bppProduct, String brainkeyProduct, String version) {
    this(BASE_URL, bppProduct, brainkeyProduct, version);
  }

  /**
   * Create a new instance of {@link VirgilPythiaClient}.
   *
   * @param baseUrl         the service url to fire requests to.
   * @param bppProduct      bpp Virgil Agent token.
   * @param brainkeyProduct brainkey Virgil agent token.
   * @param version         library version.
   */
  public VirgilPythiaClient(String baseUrl, String bppProduct, String brainkeyProduct,
      String version) {
    Validator.checkNullAgrument(baseUrl, "VirgilPythiaClient -> 'baseUrl' should not be null");
    try {
      this.baseUrl = new URL(baseUrl);
    } catch (MalformedURLException e) {
      LOGGER.log(Level.SEVERE, "Base URL has wrong format", e);
      throw new IllegalArgumentException("VirgilPythiaClient -> 'baseUrl' has wrong format");
    }
    buildVirgilAgent(bppProduct, brainkeyProduct, version);
  }

  /*
   * (non-Javadoc)
   * 
   * @see com.virgilsecurity.pythia.client.PythiaClient#transformPassword(byte[], byte[],
   * java.lang.Integer, boolean, java.lang.String)
   */
  @Override
  public TransformResponse transformPassword(byte[] salt, byte[] blindedPassword, Integer version,
      boolean includeProof, String token) throws VirgilPythiaServiceException {

    TransformPasswordRequest request = new TransformPasswordRequest(salt, blindedPassword, version,
        includeProof);

    try {
      HttpURLConnection urlConnection = createConnection("/pythia/v1/password", token);
      urlConnection.setRequestProperty(VIRGIL_AGENT_HEADER, bppVirgilAgent);
      return execute(urlConnection, request, TransformResponse.class);
    } catch (VirgilPythiaServiceException e) {
      LOGGER.log(Level.SEVERE, "Pythia service returned an error", e);
      throw e;
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "Some service issue occurred during request executing", e);
      throw new VirgilPythiaServiceException(
          "VirgilPythiaClient -> transformPassword was not successful", e);
    }
  }

  /*
   * (non-Javadoc)
   * 
   * @see com.virgilsecurity.pythia.client.PythiaClient#generateSeed(byte[], java.lang.String,
   * java.lang.String)
   */
  @Override
  public byte[] generateSeed(byte[] blindedPassword, String brainKeyId, String token)
      throws VirgilPythiaServiceException {
    GenerateSeedRequest request = new GenerateSeedRequest(blindedPassword, brainKeyId);

    try {
      HttpURLConnection urlConnection = createConnection("/pythia/v1/brainkey", token);
      urlConnection.setRequestProperty(VIRGIL_AGENT_HEADER, brainkeyVirgilAgent);
      return execute(urlConnection, request, GenerateSeedResponse.class).getSeed();
    } catch (VirgilPythiaServiceException e) {
      LOGGER.log(Level.SEVERE, "Pythia service returned an error", e);
      throw e;
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "Some service issue occurred during request executing", e);
      throw new VirgilPythiaServiceException(
          "VirgilPythiaClient -> generateSeed was not successful", e);
    }
  }

  /**
   * Create HTTP connection to Pythia service.
   * 
   * @param spec  the {@code String} to parse as a URL.
   * @param token access token.
   * @return the created connection.
   * @throws IOException if connection can't be created.
   */
  private HttpURLConnection createConnection(String spec, String token) throws IOException {
    // Create connection
    URL url = new URL(baseUrl, spec);
    HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
    urlConnection.setRequestMethod("POST");
    urlConnection.setDoOutput(true);
    urlConnection.setUseCaches(false);
    urlConnection.setRequestProperty("Content-Type", "application/json; charset=utf-8");

    // Set authorization token
    if (!StringUtils.isBlank(token)) {
      urlConnection.setRequestProperty("Authorization", "Virgil " + token);
    } else {
      LOGGER.warning("Provided token is blank");
    }

    return urlConnection;
  }

  private <T> T execute(HttpURLConnection urlConnection, Object requestBody, Class<T> clazz)
      throws IOException, VirgilPythiaServiceException {
    String body = ConvertionUtils.serializeToJson(requestBody);
    try {
      // Send payload
      urlConnection.getOutputStream().write(ConvertionUtils.toBytes(body));

      if (urlConnection.getResponseCode() >= HttpURLConnection.HTTP_BAD_REQUEST) {
        LOGGER.warning("Http error occurred...");
        HttpError httpError = new HttpError(urlConnection.getResponseCode(),
            urlConnection.getResponseMessage());

        // Get error code from request
        try (InputStream in = new BufferedInputStream(urlConnection.getErrorStream())) {
          LOGGER.fine("Trying to get error info...");
          String errBody = ConvertionUtils.toString(in);
          if (StringUtils.isBlank(errBody)) {
            throw new VirgilPythiaServiceException(httpError);
          } else {
            ErrorResponse error = ConvertionUtils.getGson().fromJson(errBody, ErrorResponse.class);
            if (error.getCode() == 60007) {
              throw new ThrottlingException(error.getCode(), error.getMessage(), httpError);
            } else {
              throw new VirgilPythiaServiceException(error.getCode(), error.getMessage(),
                  httpError);
            }
          }
        }
      } else {
        LOGGER.fine("Extracting response body...");
        try (InputStream instream = new BufferedInputStream(urlConnection.getInputStream())) {
          String responseBody = ConvertionUtils.toString(instream);
          T response = ConvertionUtils.getGson().fromJson(responseBody, clazz);
          return response;
        }
      }
    } finally {
      LOGGER.fine("Disconnecting...");
      urlConnection.disconnect();
    }
  }

  private void buildVirgilAgent(String bppProduct, String brainkeyProduct, String version) {
    String osName = OsUtils.getOsAgentName();
    this.bppVirgilAgent = String.format("%1$s;%2$s;%3$s;%4$s", bppProduct, VirgilInfo.FAMILY,
        osName, version);
    this.brainkeyVirgilAgent = String.format("%1$s;%2$s;%3$s;%4$s", brainkeyProduct,
        VirgilInfo.FAMILY, osName, version);
  }
}
