/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.litecaclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO.
 * @author Lijun Liao
 */

public class RestCaClient {

  public static final String CT_pkix_cert = "application/pkix-cert";

  private static final Logger LOG = LoggerFactory.getLogger(RestCaClient.class);

  private final String caUrl;

  private final String authorization;

  private X509Certificate caCert;

  private String caCertSha1Fp;

  public RestCaClient(String caUrl, String user, String password) throws Exception {
    this.caUrl = new URL(SdkUtil.requireNonBlank("caUrl", caUrl)).toString();
    this.authorization = Base64.getEncoder().encodeToString(
        (user + ":" + password).getBytes());
  }

  public void init() throws Exception {
    TlsInit.init();

    // Get CA certificate
    this.caCert = httpgetCaCert();
    MessageDigest md = MessageDigest.getInstance("SHA1");
    byte[] digestBytes = md.digest(this.caCert.getEncoded());
    this.caCertSha1Fp = Hex.toHexString(digestBytes);
  }

  public X509Certificate getCaCert() {
    return caCert;
  }

  public void shutdown() {
    TlsInit.shutdown();
  }

  private X509Certificate httpgetCaCert() throws Exception {
    // Get CA certificate
    byte[] bytes = httpGet(caUrl + "/cacert", CT_pkix_cert);
    return SdkUtil.parseCert(bytes);
  }

  public X509Certificate requestCert(String certProfile, CertificationRequest csr)
      throws Exception {
    String url = caUrl + "/enroll-cert?profile=" + certProfile;
    byte[] response = httpPost(url, "application/pkcs10", csr.getEncoded(), CT_pkix_cert);
    X509Certificate cert = SdkUtil.parseCert(response);
    if (!verify(caCert, cert)) {
      throw new Exception("The returned certificate is not issued by the given CA");
    }

    return cert;
  }

  public boolean revokeCert(BigInteger serialNumber, CRLReason reason) throws Exception {
    StringBuilder sb = new StringBuilder(200);
    sb.append(caUrl).append("/revoke-cert?ca-sha1=").append(caCertSha1Fp);
    sb.append("&serial-number=0X").append(serialNumber.toString(16));
    sb.append("&reason=").append(reason.getValue().intValue());
    String url = sb.toString();
    return simpleHttpGet(url);
  }

  public boolean unrevokeCert(BigInteger serialNumber) throws Exception {
    return revokeCert(serialNumber, CRLReason.lookup(CRLReason.removeFromCRL));
  }

  private boolean verify(Certificate caCert, Certificate cert) {
    if (!(caCert instanceof X509Certificate && cert instanceof X509Certificate)) {
      return false;
    }

    X509Certificate x509caCert = (X509Certificate) caCert;
    X509Certificate x509cert = (X509Certificate) cert;

    if (!x509cert.getIssuerX500Principal().equals(x509caCert.getSubjectX500Principal())) {
      return false;
    }

    PublicKey caPublicKey = x509caCert.getPublicKey();
    try {
      x509cert.verify(caPublicKey);
      return true;
    } catch (Exception ex) {
      LOG.debug("{} while verifying signature: {}", ex.getClass().getName(), ex.getMessage());
      return false;
    }
  } // method verify

  private boolean simpleHttpGet(String url) throws IOException {
    HttpURLConnection httpUrlConnection = SdkUtil.openHttpConn(new URL(url));
    httpUrlConnection.setDoOutput(true);
    httpUrlConnection.setUseCaches(false);

    httpUrlConnection.setRequestMethod("GET");
    httpUrlConnection.setRequestProperty("Authorization", "Basic " + authorization);

    int responseCode = httpUrlConnection.getResponseCode();
    boolean ok = (responseCode == HttpURLConnection.HTTP_OK);
    if (!ok) {
      LOG.warn("bad response: " + httpUrlConnection.getResponseCode() + "    "
          + httpUrlConnection.getResponseMessage());
    }
    return ok;
  } // method send

  private byte[] httpGet(String url, String responseCt) throws IOException {
    HttpURLConnection httpUrlConnection = SdkUtil.openHttpConn(new URL(url));
    httpUrlConnection.setDoOutput(true);
    httpUrlConnection.setUseCaches(false);

    httpUrlConnection.setRequestMethod("GET");
    httpUrlConnection.setRequestProperty("Authorization", "Basic " + authorization);

    InputStream inputStream = httpUrlConnection.getInputStream();
    if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
      inputStream.close();
      throw new IOException("bad response: " + httpUrlConnection.getResponseCode() + "    "
          + httpUrlConnection.getResponseMessage());
    }

    String responseContentType = httpUrlConnection.getContentType();
    boolean isValidContentType = false;
    if (responseContentType != null) {
      if (responseContentType.equalsIgnoreCase(responseCt)) {
        isValidContentType = true;
      }
    }

    if (!isValidContentType) {
      inputStream.close();
      throw new IOException("bad response: mime type " + responseContentType
          + " not supported!");
    }

    return SdkUtil.read(inputStream);
  } // method send

  private byte[] httpPost(String url, String contentType, byte[] request, String responseCt)
      throws IOException {
    SdkUtil.requireNonNull("request", request);
    HttpURLConnection httpUrlConnection = SdkUtil.openHttpConn(new URL(url));
    httpUrlConnection.setDoOutput(true);
    httpUrlConnection.setUseCaches(false);

    int size = request.length;

    httpUrlConnection.setRequestMethod("POST");
    httpUrlConnection.setRequestProperty("Content-Type", contentType);
    httpUrlConnection.setRequestProperty("Content-Length", java.lang.Integer.toString(size));
    httpUrlConnection.setRequestProperty("Authorization", "Basic " + authorization);
    OutputStream outputstream = httpUrlConnection.getOutputStream();
    outputstream.write(request);
    outputstream.flush();

    InputStream inputStream = httpUrlConnection.getInputStream();
    if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
      inputStream.close();
      throw new IOException("bad response: " + httpUrlConnection.getResponseCode() + "    "
          + httpUrlConnection.getResponseMessage());
    }

    String responseContentType = httpUrlConnection.getContentType();
    boolean isValidContentType = false;
    if (responseContentType != null) {
      if (responseContentType.equalsIgnoreCase(responseCt)) {
        isValidContentType = true;
      }
    }

    if (!isValidContentType) {
      inputStream.close();
      throw new IOException("bad response: mime type " + responseContentType
          + " not supported!");
    }

    return SdkUtil.read(inputStream);
  } // method send

}
