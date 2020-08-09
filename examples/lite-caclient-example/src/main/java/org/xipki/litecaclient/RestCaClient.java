/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CA client which communicates with CA via REST API.
 *
 * @author Lijun Liao
 */

public class RestCaClient implements Closeable {

  public static final String CT_PEM_FILE = "application/x-pem-file";

  public static final String CT_PKIX_CERT = "application/pkix-cert";

  private static final Logger LOG = LoggerFactory.getLogger(RestCaClient.class);

  private final String caUrl;

  private final String authorization;

  private X509Certificate caCert;

  private List<X509Certificate> caCertchain;

  private String caCertSha1Fp;

  public RestCaClient(String caUrl, String user, String password)
      throws Exception {
    this.caUrl = new URL(SdkUtil.requireNonBlank("caUrl", caUrl)).toString();
    this.authorization = Base64.getEncoder().encodeToString(
                            (user + ":" + password).getBytes(StandardCharsets.UTF_8));
  }

  public void init()
      throws Exception {
    TlsInit.init();

    // Get CA certificate
    this.caCertchain = httpgetCaCertchain();
    this.caCert = this.caCertchain.get(0);
    MessageDigest md = MessageDigest.getInstance("SHA1");
    byte[] digestBytes = md.digest(this.caCert.getEncoded());
    this.caCertSha1Fp = Hex.toHexString(digestBytes);
  } // method init

  public X509Certificate getCaCert() {
    return caCert;
  }

  @Override
  public void close() {
    TlsInit.close();
  }

  private List<X509Certificate> httpgetCaCertchain()
      throws Exception {
    List<X509Certificate> certchain = new LinkedList<>();
    // Get CA certificate chain
    byte[] bytes = httpGet(caUrl + "/cacertchain", CT_PEM_FILE);
    try (PemReader pemReader =
        new PemReader(new InputStreamReader(new ByteArrayInputStream(bytes)))) {
      PemObject pemObject;
      while ((pemObject = pemReader.readPemObject()) != null) {
        if ("CERTIFICATE".contentEquals(pemObject.getType())) {
          certchain.add(SdkUtil.parseCert(pemObject.getContent()));
        }
      }
    }

    if (certchain.isEmpty()) {
      throw new Exception("could not retrieve certificates");
    }
    return certchain;
  } // method httpgetCaCertchain

  public X509Certificate requestCert(String certprofile, CertificationRequest csr)
      throws Exception {
    String url = caUrl + "/enroll-cert?profile=" + certprofile;
    byte[] response = httpPost(url, "application/pkcs10", csr.getEncoded(), CT_PKIX_CERT);
    X509Certificate cert = SdkUtil.parseCert(response);
    if (!verify(caCert, cert)) {
      throw new Exception("The returned certificate is not issued by the given CA");
    }

    return cert;
  } // method requestCert

  public boolean revokeCert(BigInteger serialNumber, CRLReason reason)
      throws Exception {
    StringBuilder sb = new StringBuilder(200);
    sb.append(caUrl).append("/revoke-cert?ca-sha1=").append(caCertSha1Fp);
    sb.append("&serial-number=0X").append(serialNumber.toString(16));
    sb.append("&reason=").append(reason.getValue().intValue());
    String url = sb.toString();
    return simpleHttpGet(url);
  } // method revokeCert

  public boolean unrevokeCert(BigInteger serialNumber)
      throws Exception {
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

  private boolean simpleHttpGet(String url)
      throws IOException {
    HttpURLConnection conn = SdkUtil.openHttpConn(new URL(url));
    conn.setDoOutput(true);
    conn.setUseCaches(false);

    conn.setRequestMethod("GET");
    conn.setRequestProperty("Authorization", "Basic " + authorization);

    int responseCode = conn.getResponseCode();
    boolean ok = (responseCode == HttpURLConnection.HTTP_OK);
    if (!ok) {
      LOG.warn("bad response: {}    {}", conn.getResponseCode(), conn.getResponseMessage());
    }
    return ok;
  } // method simpleHttpGet

  private byte[] httpGet(String url, String responseCt)
      throws IOException {
    HttpURLConnection conn = SdkUtil.openHttpConn(new URL(url));
    conn.setDoOutput(true);
    conn.setUseCaches(false);

    conn.setRequestMethod("GET");
    conn.setRequestProperty("Authorization", "Basic " + authorization);

    InputStream inputStream = conn.getInputStream();
    if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
      inputStream.close();
      throw new IOException("bad response: " + conn.getResponseCode() + "    "
          + conn.getResponseMessage());
    }

    String responseContentType = conn.getContentType();
    boolean isValidContentType = false;
    if (responseContentType != null) {
      if (responseContentType.equalsIgnoreCase(responseCt)) {
        isValidContentType = true;
      }
    }

    if (!isValidContentType) {
      inputStream.close();
      throw new IOException("bad response: mime type " + responseContentType + " not supported!");
    }

    return SdkUtil.read(inputStream);
  } // method httpGet

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
      throw new IOException("bad response: mime type " + responseContentType + " not supported!");
    }

    return SdkUtil.read(inputStream);
  } // method httpPost

}
