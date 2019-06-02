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

package org.xipki.scep.client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.scep.client.exception.OperationNotSupportedException;
import org.xipki.scep.client.exception.ScepClientException;
import org.xipki.scep.crypto.ScepHashAlgo;
import org.xipki.scep.exception.MessageDecodingException;
import org.xipki.scep.exception.MessageEncodingException;
import org.xipki.scep.message.AuthorityCertStore;
import org.xipki.scep.message.CaCaps;
import org.xipki.scep.message.DecodedNextCaMessage;
import org.xipki.scep.message.DecodedPkiMessage;
import org.xipki.scep.message.IssuerAndSubject;
import org.xipki.scep.message.PkiMessage;
import org.xipki.scep.transaction.CaCapability;
import org.xipki.scep.transaction.MessageType;
import org.xipki.scep.transaction.Operation;
import org.xipki.scep.transaction.PkiStatus;
import org.xipki.scep.transaction.TransactionId;
import org.xipki.scep.util.ScepConstants;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public abstract class Client {

  public static final String REQ_CONTENT_TYPE = "application/octet-stream";

  // 5 minutes
  public static final long DEFAULT_SIGNINGTIME_BIAS = 5L * 60 * 1000;

  protected final CaIdentifier caId;

  protected CaCaps caCaps;

  private final CaCertValidator caCertValidator;

  private long maxSigningTimeBiasInMs = DEFAULT_SIGNINGTIME_BIAS;

  private AuthorityCertStore authorityCertStore;

  private CollectionStore<X509CertificateHolder> responseSignerCerts;

  private boolean httpGetOnly;

  private boolean useInsecureAlgorithms;

  public Client(CaIdentifier caId, CaCertValidator caCertValidator) throws MalformedURLException {
    this.caId = ScepUtil.requireNonNull("caId", caId);
    this.caCertValidator = ScepUtil.requireNonNull("caCertValidator", caCertValidator);
  }

  /**
   * TODO.
   * @param url
   *          SCEP server URL. Must not be {@code null}.
   * @param requestContentType
   *          Content type of the HTTP request. Must not be {@code null}.
   * @param request
   *          HTTP request. Must not be {@code null}.
   * @return the SCEP response
   * @throws ScepClientException
   *          If error happens
   */
  protected abstract ScepHttpResponse httpPost(String url, String requestContentType,
      byte[] request) throws ScepClientException;

  /**
   * TODO.
   * @param url
   *          URL. Must not be {@code null}.
   */
  protected abstract ScepHttpResponse httpGet(String url) throws ScepClientException;

  public boolean isHttpGetOnly() {
    return httpGetOnly;
  }

  public void setHttpGetOnly(boolean httpGetOnly) {
    this.httpGetOnly = httpGetOnly;
  }

  public boolean isUseInsecureAlgorithms() {
    return useInsecureAlgorithms;
  }

  public void setUseInsecureAlgorithms(boolean useInsecureAlgorithms) {
    this.useInsecureAlgorithms = useInsecureAlgorithms;
  }

  public long getMaxSigningTimeBiasInMs() {
    return maxSigningTimeBiasInMs;
  }

  /**
   * Set the maximal signing time bias in milliseconds.
   * @param maxSigningTimeBiasInMs zero or negative value deactivates the message time check
   */
  public void setMaxSigningTimeBiasInMs(long maxSigningTimeBiasInMs) {
    this.maxSigningTimeBiasInMs = maxSigningTimeBiasInMs;
  }

  private ScepHttpResponse httpSend(Operation operation, ContentInfo pkiMessage)
      throws ScepClientException {
    byte[] request = null;
    if (pkiMessage != null) {
      try {
        request = pkiMessage.getEncoded();
      } catch (IOException ex) {
        throw new ScepClientException(ex);
      }
    }

    if (Operation.GetCACaps == operation || Operation.GetCACert == operation
        || Operation.GetNextCACert == operation) {
      String url = caId.buildGetUrl(operation, caId.getProfile());
      return httpGet(url);
    } else {
      if (!httpGetOnly && caCaps.containsCapability(CaCapability.POSTPKIOperation)) {
        String url = caId.buildPostUrl(operation);
        return httpPost(url, REQ_CONTENT_TYPE, request);
      } else {
        String url = caId.buildGetUrl(operation,
            (request == null) ? null : new String(Base64.encode(request)));
        return httpGet(url);
      }
    } // end if
  }

  private ScepHttpResponse httpSend(Operation operation) throws ScepClientException {
    return httpSend(operation, null);
  }

  public void init() throws ScepClientException {
    refresh();
  }

  public void refresh() throws ScepClientException {
    // getCACaps
    ScepHttpResponse getCaCapsResp = httpSend(Operation.GetCACaps);
    this.caCaps = CaCaps.getInstance(new String(getCaCapsResp.getContentBytes()));

    // getCACert
    ScepHttpResponse getCaCertResp = httpSend(Operation.GetCACert);
    this.authorityCertStore = retrieveCaCertStore(getCaCertResp, caCertValidator);

    X509CertificateHolder certHolder;
    try {
      certHolder =
          new X509CertificateHolder(this.authorityCertStore.getSignatureCert().getEncoded());
    } catch (CertificateEncodingException ex) {
      throw new ScepClientException(ex);
    } catch (IOException ex) {
      throw new ScepClientException(ex);
    }
    this.responseSignerCerts = new CollectionStore<X509CertificateHolder>(
        Arrays.asList(certHolder));
  }

  public CaCaps getCaCaps() throws ScepClientException {
    initIfNotInited();
    return caCaps;
  }

  public X509Certificate getCaCert() {
    return authorityCertStore == null ? null : authorityCertStore.getCaCert();
  }

  public CaIdentifier getCaId() throws ScepClientException {
    initIfNotInited();
    return caId;
  }

  public CaCertValidator getCaCertValidator() throws ScepClientException {
    initIfNotInited();
    return caCertValidator;
  }

  public AuthorityCertStore getAuthorityCertStore() throws ScepClientException {
    initIfNotInited();
    return authorityCertStore;
  }

  public X509CRL scepGetCrl(PrivateKey identityKey, X509Certificate identityCert, X500Name issuer,
      BigInteger serialNumber) throws ScepClientException {
    ScepUtil.requireNonNull("identityKey", identityKey);
    ScepUtil.requireNonNull("identityCert", identityCert);
    ScepUtil.requireNonNull("issuer", issuer);
    ScepUtil.requireNonNull("serialNumber", serialNumber);

    initIfNotInited();

    PkiMessage pkiMessage = new PkiMessage(TransactionId.randomTransactionId(), MessageType.GetCRL);
    IssuerAndSerialNumber isn = new IssuerAndSerialNumber(issuer, serialNumber);
    pkiMessage.setMessageData(isn);
    ContentInfo request = encryptThenSign(pkiMessage, identityKey, identityCert);
    ScepHttpResponse httpResp = httpSend(Operation.PKIOperation, request);
    CMSSignedData cmsSignedData = parsePkiMessage(httpResp.getContentBytes());
    PkiMessage response = decode(cmsSignedData, identityKey, identityCert);
    if (response.getPkiStatus() != PkiStatus.SUCCESS) {
      throw new ScepClientException("server returned " + response.getPkiStatus());
    }

    ContentInfo messageData = ContentInfo.getInstance(response.getMessageData());

    try {
      return ScepUtil.getCrlFromPkiMessage(SignedData.getInstance(messageData.getContent()));
    } catch (CRLException ex) {
      throw new ScepClientException(ex.getMessage(), ex);
    }
  }

  public List<X509Certificate> scepGetCert(PrivateKey identityKey, X509Certificate identityCert,
      X500Name issuer, BigInteger serialNumber) throws ScepClientException {
    ScepUtil.requireNonNull("identityKey", identityKey);
    ScepUtil.requireNonNull("identityCert", identityCert);
    ScepUtil.requireNonNull("issuer", issuer);
    ScepUtil.requireNonNull("serialNumber", serialNumber);

    initIfNotInited();

    PkiMessage request = new PkiMessage(TransactionId.randomTransactionId(), MessageType.GetCert);

    IssuerAndSerialNumber isn = new IssuerAndSerialNumber(issuer, serialNumber);
    request.setMessageData(isn);
    ContentInfo envRequest = encryptThenSign(request, identityKey, identityCert);
    ScepHttpResponse httpResp = httpSend(Operation.PKIOperation, envRequest);

    CMSSignedData cmsSignedData = parsePkiMessage(httpResp.getContentBytes());
    DecodedPkiMessage response = decode(cmsSignedData, identityKey, identityCert);
    if (response.getPkiStatus() != PkiStatus.SUCCESS) {
      throw new ScepClientException("server returned " + response.getPkiStatus());
    }

    ContentInfo messageData = ContentInfo.getInstance(response.getMessageData());
    try {
      return ScepUtil.getCertsFromSignedData(SignedData.getInstance(messageData.getContent()));
    } catch (CertificateException ex) {
      throw new ScepClientException(ex.getMessage(), ex);
    }
  }

  public EnrolmentResponse scepCertPoll(PrivateKey identityKey, X509Certificate identityCert,
      CertificationRequest csr, X500Name issuer) throws ScepClientException {
    ScepUtil.requireNonNull("csr", csr);

    TransactionId tid;
    try {
      tid = TransactionId.sha1TransactionId(
          csr.getCertificationRequestInfo().getSubjectPublicKeyInfo());
    } catch (InvalidKeySpecException ex) {
      throw new ScepClientException(ex.getMessage(), ex);
    }

    return scepCertPoll(identityKey, identityCert, tid, issuer,
        csr.getCertificationRequestInfo().getSubject());
  }

  public EnrolmentResponse scepCertPoll(PrivateKey identityKey, X509Certificate identityCert,
      TransactionId transactionId, X500Name issuer, X500Name subject) throws ScepClientException {
    ScepUtil.requireNonNull("identityKey", identityKey);
    ScepUtil.requireNonNull("identityCert", identityCert);
    ScepUtil.requireNonNull("issuer", issuer);
    ScepUtil.requireNonNull("transactionId", transactionId);

    initIfNotInited();

    PkiMessage pkiMessage = new PkiMessage(transactionId, MessageType.CertPoll);

    IssuerAndSubject is = new IssuerAndSubject(issuer, subject);
    pkiMessage.setMessageData(is);
    ContentInfo envRequest = encryptThenSign(pkiMessage, identityKey, identityCert);
    ScepHttpResponse httpResp = httpSend(Operation.PKIOperation, envRequest);
    CMSSignedData cmsSignedData = parsePkiMessage(httpResp.getContentBytes());
    DecodedPkiMessage response = decode(cmsSignedData, identityKey, identityCert);
    assertSameNonce(pkiMessage, response);
    return new EnrolmentResponse(response);
  }

  public EnrolmentResponse scepEnrol(CertificationRequest csr, PrivateKey identityKey,
      X509Certificate identityCert) throws ScepClientException {
    ScepUtil.requireNonNull("csr", csr);
    ScepUtil.requireNonNull("identityKey", identityKey);
    ScepUtil.requireNonNull("identityCert", identityCert);

    initIfNotInited();

    // draft-nourse-scep
    if (!isGutmannScep()) {
      return scepPkcsReq(csr, identityKey, identityCert);
    }

    // draft-gutmann-scep
    if (!ScepUtil.isSelfSigned(identityCert)) {
      X509Certificate caCert = authorityCertStore.getCaCert();
      if (identityCert.getIssuerX500Principal().equals(caCert.getSubjectX500Principal())) {
        if (caCaps.containsCapability(CaCapability.Renewal)) {
          return scepRenewalReq(csr, identityKey, identityCert);
        }
      } else {
        if (caCaps.containsCapability(CaCapability.Update)) {
          return scepUpdateReq(csr, identityKey, identityCert);
        }
      }
    } // end if

    return scepPkcsReq(csr, identityKey, identityCert);
  }

  public EnrolmentResponse scepPkcsReq(CertificationRequest csr, PrivateKey identityKey,
      X509Certificate identityCert) throws ScepClientException {
    ScepUtil.requireNonNull("csr", csr);
    ScepUtil.requireNonNull("identityKey", identityKey);
    ScepUtil.requireNonNull("identityCert", identityCert);

    initIfNotInited();

    if (!ScepUtil.isSelfSigned(identityCert)) {
      throw new IllegalArgumentException("identityCert is not self-signed");
    }

    return enroll(MessageType.PKCSReq, csr, identityKey, identityCert);
  }

  public EnrolmentResponse scepRenewalReq(CertificationRequest csr, PrivateKey identityKey,
      X509Certificate identityCert) throws ScepClientException {
    initIfNotInited();

    if (!caCaps.containsCapability(CaCapability.Renewal)) {
      throw new OperationNotSupportedException(
          "unsupported messageType '" + MessageType.RenewalReq + "'");
    }

    boolean selfSigned = ScepUtil.isSelfSigned(identityCert);
    if (selfSigned) {
      throw new IllegalArgumentException("identityCert must not be self-signed");
    }

    return enroll(MessageType.RenewalReq, csr, identityKey, identityCert);
  }

  public EnrolmentResponse scepUpdateReq(CertificationRequest csr, PrivateKey identityKey,
      X509Certificate identityCert) throws ScepClientException {
    initIfNotInited();

    if (!caCaps.containsCapability(CaCapability.Update)) {
      throw new OperationNotSupportedException(
          "unsupported messageType '" + MessageType.UpdateReq + "'");
    }

    boolean selfSigned = ScepUtil.isSelfSigned(identityCert);
    if (selfSigned) {
      throw new IllegalArgumentException("identityCert must not be self-signed");
    }

    return enroll(MessageType.UpdateReq, csr, identityKey, identityCert);
  }

  private EnrolmentResponse enroll(MessageType messageType, CertificationRequest csr,
      PrivateKey identityKey, X509Certificate identityCert) throws ScepClientException {
    TransactionId tid;
    try {
      tid = TransactionId.sha1TransactionId(
          csr.getCertificationRequestInfo().getSubjectPublicKeyInfo());
    } catch (InvalidKeySpecException ex) {
      throw new ScepClientException(ex.getMessage(), ex);
    }
    PkiMessage pkiMessage = new PkiMessage(tid, messageType);

    pkiMessage.setMessageData(csr);
    ContentInfo envRequest = encryptThenSign(pkiMessage, identityKey, identityCert);
    ScepHttpResponse httpResp = httpSend(Operation.PKIOperation, envRequest);

    CMSSignedData cmsSignedData = parsePkiMessage(httpResp.getContentBytes());
    DecodedPkiMessage response = decode(cmsSignedData, identityKey, identityCert);
    assertSameNonce(pkiMessage, response);
    return new EnrolmentResponse(response);
  }

  public AuthorityCertStore scepNextCaCert() throws ScepClientException {
    initIfNotInited();

    if (!this.caCaps.containsCapability(CaCapability.GetNextCACert)) {
      throw new OperationNotSupportedException(
              "unsupported operation '" + Operation.GetNextCACert.getCode() + "'");
    }

    ScepHttpResponse resp = httpSend(Operation.GetNextCACert);
    return retrieveNextCaAuthorityCertStore(resp);
  }

  private ContentInfo encryptThenSign(PkiMessage request, PrivateKey identityKey,
      X509Certificate identityCert) throws ScepClientException {
    ScepHashAlgo hashAlgo = caCaps.mostSecureHashAlgo();
    if (hashAlgo == ScepHashAlgo.MD5 && !useInsecureAlgorithms) {
      throw new ScepClientException("Scep server supports only MD5 but it not permitted in client");
    }
    String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(identityKey, hashAlgo);
    ASN1ObjectIdentifier encAlgId;
    if (caCaps.containsCapability(CaCapability.AES)) {
      encAlgId = CMSAlgorithm.AES128_CBC;
    } else if (caCaps.containsCapability(CaCapability.DES3)) {
      encAlgId = CMSAlgorithm.DES_EDE3_CBC;
    } else if (useInsecureAlgorithms) {
      encAlgId = CMSAlgorithm.DES_CBC;
    } else { // no support of DES
      throw new ScepClientException("DES will not be supported by this client");
    }

    try {
      return request.encode(identityKey, signatureAlgorithm, identityCert,
          new X509Certificate[]{identityCert}, authorityCertStore.getEncryptionCert(), encAlgId);
    } catch (MessageEncodingException ex) {
      throw new ScepClientException(ex);
    }
  }

  public void destroy() {
  }

  private AuthorityCertStore retrieveNextCaAuthorityCertStore(ScepHttpResponse httpResp)
      throws ScepClientException {
    String ct = httpResp.getContentType();

    if (!ScepConstants.CT_X509_NEXT_CA_CERT.equalsIgnoreCase(ct)) {
      throw new ScepClientException("invalid Content-Type '" + ct + "'");
    }

    CMSSignedData cmsSignedData;
    try {
      cmsSignedData = new CMSSignedData(httpResp.getContentBytes());
    } catch (CMSException ex) {
      throw new ScepClientException("invalid SignedData message: " + ex.getMessage(), ex);
    } catch (IllegalArgumentException ex) {
      throw new ScepClientException("invalid SignedData message: " + ex.getMessage(), ex);
    }

    DecodedNextCaMessage resp;
    try {
      resp = DecodedNextCaMessage.decode(cmsSignedData, responseSignerCerts);
    } catch (MessageDecodingException ex) {
      throw new ScepClientException("could not decode response: " + ex.getMessage(), ex);
    }

    if (resp.getFailureMessage() != null) {
      throw new ScepClientException("Error: " + resp.getFailureMessage());
    }

    Boolean bo = resp.isSignatureValid();
    if (bo != null && !bo.booleanValue()) {
      throw new ScepClientException("Signature is invalid");
    }

    Date signingTime = resp.getSigningTime();
    long maxSigningTimeBias = getMaxSigningTimeBiasInMs();
    if (maxSigningTimeBias > 0) {
      if (signingTime == null) {
        throw new ScepClientException("CMS signingTime attribute is not present");
      }

      long now = System.currentTimeMillis();
      long diff = now - signingTime.getTime();
      if (diff < 0) {
        diff = -1 * diff;
      }

      if (diff > maxSigningTimeBias) {
        throw new ScepClientException("CMS signingTime is out of permitted period");
      }
    }

    if (!resp.getSignatureCert().equals(authorityCertStore.getSignatureCert())) {
      throw new ScepClientException("the signature certificate must not be trusted");
    }

    return resp.getAuthorityCertStore();
  } // method retrieveNextCaAuthorityCertStore

  private void initIfNotInited() throws ScepClientException {
    if (caCaps == null) {
      init();
    }
  }

  private DecodedPkiMessage decode(CMSSignedData pkiMessage, PrivateKey recipientKey,
      X509Certificate recipientCert) throws ScepClientException {
    DecodedPkiMessage resp;
    try {
      resp = DecodedPkiMessage.decode(pkiMessage, recipientKey, recipientCert, responseSignerCerts);
    } catch (MessageDecodingException ex) {
      throw new ScepClientException(ex);
    }

    if (resp.getFailureMessage() != null) {
      throw new ScepClientException("Error: " + resp.getFailureMessage());
    }

    Boolean bo = resp.isSignatureValid();
    if (bo != null && !bo.booleanValue()) {
      throw new ScepClientException("Signature is invalid");
    }

    bo = resp.isDecryptionSuccessful();
    if (bo != null && !bo.booleanValue()) {
      throw new ScepClientException("Decryption failed");
    }

    Date signingTime = resp.getSigningTime();
    long maxSigningTimeBias = getMaxSigningTimeBiasInMs();
    if (maxSigningTimeBias > 0) {
      if (signingTime == null) {
        throw new ScepClientException("CMS signingTime attribute is not present");
      }

      long now = System.currentTimeMillis();
      long diff = now - signingTime.getTime();
      if (diff < 0) {
        diff = -1 * diff;
      }
      if (diff > maxSigningTimeBias) {
        throw new ScepClientException("CMS signingTime is out of permitted period");
      }
    }

    if (!resp.getSignatureCert().equals(authorityCertStore.getSignatureCert())) {
      throw new ScepClientException("the signature certificate must not be trusted");
    }
    return resp;
  } // method decode

  private boolean isGutmannScep() {
    return caCaps.containsCapability(CaCapability.AES)
        || caCaps.containsCapability(CaCapability.Update);
  }

  private static X509Certificate parseCert(byte[] certBytes) throws ScepClientException {
    try {
      return ScepUtil.parseCert(certBytes);
    } catch (CertificateException ex) {
      throw new ScepClientException(ex);
    }
  }

  private static CMSSignedData parsePkiMessage(byte[] messageBytes) throws ScepClientException {
    try {
      return new CMSSignedData(messageBytes);
    } catch (CMSException ex) {
      throw new ScepClientException(ex);
    }
  }

  private static AuthorityCertStore retrieveCaCertStore(ScepHttpResponse resp,
      CaCertValidator caValidator) throws ScepClientException {
    String ct = resp.getContentType();

    X509Certificate caCert = null;
    List<X509Certificate> raCerts = new LinkedList<X509Certificate>();

    if (ScepConstants.CT_X509_CA_CERT.equalsIgnoreCase(ct)) {
      caCert = parseCert(resp.getContentBytes());
    } else if (ScepConstants.CT_X509_CA_RA_CERT.equalsIgnoreCase(ct)) {
      ContentInfo contentInfo = ContentInfo.getInstance(resp.getContentBytes());

      SignedData signedData;
      try {
        signedData = SignedData.getInstance(contentInfo.getContent());
      } catch (IllegalArgumentException ex) {
        throw new ScepClientException("invalid SignedData message: " + ex.getMessage(), ex);
      }

      List<X509Certificate> certs;
      try {
        certs = ScepUtil.getCertsFromSignedData(signedData);
      } catch (CertificateException ex) {
        throw new ScepClientException(ex.getMessage(), ex);
      }

      final int n = certs.size();
      if (n < 2) {
        throw new ScepClientException(
            "at least 2 certificates are expected, but only " + n + " is available");
      }

      for (int i = 0; i < n; i++) {
        X509Certificate cert = certs.get(i);
        if (cert.getBasicConstraints() > -1) {
          if (caCert != null) {
            throw new ScepClientException(
                "multiple CA certificates is returned, but exactly 1 is expected");
          }
          caCert = cert;
        } else {
          raCerts.add(cert);
        }
      }

      if (caCert == null) {
        throw new ScepClientException("no CA certificate is returned");
      }
    } else {
      throw new ScepClientException("invalid Content-Type '" + ct + "'");
    }

    if (!caValidator.isTrusted(caCert)) {
      throw new ScepClientException(
          "CA certificate '" + caCert.getSubjectX500Principal() + "' is not trusted");
    }

    if (raCerts.isEmpty()) {
      return AuthorityCertStore.getInstance(caCert);
    } else {
      AuthorityCertStore cs = AuthorityCertStore.getInstance(caCert,
          raCerts.toArray(new X509Certificate[0]));
      X509Certificate raEncCert = cs.getEncryptionCert();
      X509Certificate raSignCert = cs.getSignatureCert();
      try {
        if (!ScepUtil.issues(caCert, raEncCert)) {
          throw new ScepClientException("RA certificate '"
              + raEncCert.getSubjectX500Principal() + " is not issued by the CA");
        }
        if (raSignCert != raEncCert && ScepUtil.issues(caCert, raSignCert)) {
          throw new ScepClientException("RA certificate '"
              + raSignCert.getSubjectX500Principal() + " is not issued by the CA");
        }
      } catch (CertificateException ex) {
        throw new ScepClientException("invalid certificate: " + ex.getMessage(), ex);
      }

      return cs;
    }
  } // method retrieveCaCertStore

  private static void assertSameNonce(PkiMessage request, PkiMessage response)
      throws ScepClientException {
    if (request.getSenderNonce().equals(response.getRecipientNonce())) {
      throw new ScepClientException("SenderNonce in request != RecipientNonce in response");
    }
  }

}
