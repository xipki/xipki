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

package org.xipki.scep.client;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.CollectionStore;
import org.xipki.scep.client.ScepClientException.OperationNotSupportedException;
import org.xipki.scep.message.*;
import org.xipki.scep.transaction.MessageType;
import org.xipki.scep.transaction.Operation;
import org.xipki.scep.transaction.PkiStatus;
import org.xipki.scep.transaction.TransactionId;
import org.xipki.scep.util.ScepConstants;
import org.xipki.scep.util.ScepUtil;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.StringUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * SCEP client.
 *
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

  public Client(CaIdentifier caId, CaCertValidator caCertValidator) {
    this.caId = Args.notNull(caId, "caId");
    this.caCertValidator = Args.notNull(caCertValidator, "caCertValidator");
  }

  /**
   * Send request via HTTP POST.
   *
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
  protected abstract ScepHttpResponse httpPost(String url, String requestContentType, byte[] request)
      throws ScepClientException;

  /**
   * Send request via HTTP GET.
   *
   * @param url
   *          URL. Must not be {@code null}.
   * @return the response.
   * @throws ScepClientException
   *           If error occurs.
   */
  protected abstract ScepHttpResponse httpGet(String url) throws ScepClientException;

  public boolean isHttpGetOnly() {
    return httpGetOnly;
  }

  public void setHttpGetOnly(boolean httpGetOnly) {
    this.httpGetOnly = httpGetOnly;
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

    if (Operation.GetCACaps == operation || Operation.GetCACert == operation || Operation.GetNextCACert == operation) {
      String url = caId.buildGetUrl(operation, caId.getProfile());
      return httpGet(url);
    } else {
      if (!httpGetOnly && caCaps.supportsPost()) {
        String url = caId.buildPostUrl(operation);
        return httpPost(url, REQ_CONTENT_TYPE, request);
      } else {
        String url = caId.buildGetUrl(operation, (request == null) ? null : Base64.encodeToString(request));
        return httpGet(url);
      }
    } // end if
  } // method httpSend

  private ScepHttpResponse httpSend(Operation operation) throws ScepClientException {
    return httpSend(operation, null);
  }

  public void init() throws ScepClientException {
    refresh();
  }

  public void refresh() throws ScepClientException {
    // getCACaps
    ScepHttpResponse getCaCapsResp = httpSend(Operation.GetCACaps);
    this.caCaps = CaCaps.getInstance(StringUtil.toUtf8String(getCaCapsResp.getContentBytes()));

    // getCACert
    ScepHttpResponse getCaCertResp = httpSend(Operation.GetCACert);
    this.authorityCertStore = retrieveCaCertStore(getCaCertResp, caCertValidator);

    X509CertificateHolder certHolder;
    try {
      certHolder = new X509CertificateHolder(this.authorityCertStore.getSignatureCert().getEncoded());
    } catch (IOException ex) {
      throw new ScepClientException(ex);
    }
    this.responseSignerCerts = new CollectionStore<>(Collections.singletonList(certHolder));
  } // method refresh

  public CaCaps getCaCaps() throws ScepClientException {
    initIfNotInited();
    return caCaps;
  }

  public X509Cert getCaCert() {
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

  public X509CRLHolder scepGetCrl(
      PrivateKey identityKey, X509Cert identityCert, X500Name issuer, BigInteger serialNumber)
      throws ScepClientException {
    Args.notNull(identityKey, "identityKey");
    Args.notNull(identityCert, "identityCert");
    Args.notNull(issuer, "issuer");
    Args.notNull(serialNumber, "serialNumber");

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
  } // method scepGetCrl

  public List<X509Cert> scepGetCert(
      PrivateKey identityKey, X509Cert identityCert, X500Name issuer, BigInteger serialNumber)
      throws ScepClientException {
    Args.notNull(identityKey, "identityKey");
    Args.notNull(identityCert, "identityCert");
    Args.notNull(issuer, "issuer");
    Args.notNull(serialNumber, "serialNumber");

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
  } // method scepGetCert

  public EnrolmentResponse scepCertPoll(
      PrivateKey identityKey, X509Cert identityCert, CertificationRequest csr, X500Name issuer)
      throws ScepClientException {
    Args.notNull(csr, "csr");

    TransactionId tid;
    try {
      tid = TransactionId.sha1TransactionId(csr.getCertificationRequestInfo().getSubjectPublicKeyInfo());
    } catch (InvalidKeySpecException ex) {
      throw new ScepClientException(ex.getMessage(), ex);
    }

    return scepCertPoll(identityKey, identityCert, tid, issuer, csr.getCertificationRequestInfo().getSubject());
  } // method scepCertPoll

  public EnrolmentResponse scepCertPoll(
      PrivateKey identityKey, X509Cert identityCert, TransactionId transactionId, X500Name issuer, X500Name subject)
      throws ScepClientException {
    Args.notNull(identityKey, "identityKey");
    Args.notNull(identityCert, "identityCert");
    Args.notNull(issuer, "issuer");
    Args.notNull(transactionId, "transactionId");

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
  } // method scepCertPoll

  public EnrolmentResponse scepEnrol(CertificationRequest csr, PrivateKey identityKey, X509Cert identityCert)
      throws ScepClientException {
    Args.notNull(csr, "csr");
    Args.notNull(identityKey, "identityKey");
    Args.notNull(identityCert, "identityCert");

    initIfNotInited();

    if (!identityCert.isSelfSigned()) {
      if (caCaps.supportsRenewal()) {
        return scepRenewalReq(csr, identityKey, identityCert);
      }
    } // end if

    return scepPkcsReq(csr, identityKey, identityCert);
  } // method scepEnrol

  public EnrolmentResponse scepPkcsReq(CertificationRequest csr, PrivateKey identityKey, X509Cert identityCert)
      throws ScepClientException {
    Args.notNull(csr, "csr");
    Args.notNull(identityKey, "identityKey");
    Args.notNull(identityCert, "identityCert");

    initIfNotInited();

    if (!identityCert.isSelfSigned()) {
      throw new IllegalArgumentException("identityCert is not self-signed");
    }

    return enroll(MessageType.PKCSReq, csr, identityKey, identityCert);
  } // method scepPkcsReq

  public EnrolmentResponse scepRenewalReq(CertificationRequest csr, PrivateKey identityKey, X509Cert identityCert)
      throws ScepClientException {
    initIfNotInited();

    if (!caCaps.supportsRenewal()) {
      throw new OperationNotSupportedException("unsupported messageType '" + MessageType.RenewalReq + "'");
    }

    if (identityCert.isSelfSigned()) {
      throw new IllegalArgumentException("identityCert must not be self-signed");
    }

    return enroll(MessageType.RenewalReq, csr, identityKey, identityCert);
  } // method scepRenewalReq

  private EnrolmentResponse enroll(
      MessageType messageType, CertificationRequest csr, PrivateKey identityKey, X509Cert identityCert)
      throws ScepClientException {
    TransactionId tid;
    try {
      tid = TransactionId.sha1TransactionId(csr.getCertificationRequestInfo().getSubjectPublicKeyInfo());
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
  } // method enroll

  public AuthorityCertStore scepNextCaCert() throws ScepClientException {
    initIfNotInited();

    if (!this.caCaps.supportsGetNextCACert()) {
      throw new OperationNotSupportedException("unsupported operation '" + Operation.GetNextCACert.getCode() + "'");
    }

    ScepHttpResponse resp = httpSend(Operation.GetNextCACert);
    return retrieveNextCaAuthorityCertStore(resp);
  } // method scepNextCaCert

  private ContentInfo encryptThenSign(PkiMessage request, PrivateKey identityKey, X509Cert identityCert)
      throws ScepClientException {
    HashAlgo hashAlgo = caCaps.mostSecureHashAlgo();
    ASN1ObjectIdentifier encAlgId;
    if (caCaps.supportsAES()) {
      encAlgId = CMSAlgorithm.AES128_CBC;
    } else if (caCaps.supportsDES3()) {
      encAlgId = CMSAlgorithm.DES_EDE3_CBC;
    } else {
      throw new ScepClientException("DES will not be supported by this client");
    }

    try {
      SignAlgo signatureAlgorithm = SignAlgo.getInstance(identityKey, hashAlgo, null);
      return request.encode(identityKey, signatureAlgorithm, identityCert,
          new X509Cert[]{identityCert}, authorityCertStore.getEncryptionCert(), encAlgId);
    } catch (MessageEncodingException | NoSuchAlgorithmException ex) {
      throw new ScepClientException(ex);
    }
  } // method encryptThenSign

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
    } catch (CMSException | IllegalArgumentException ex) {
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
    if (bo != null && !bo) {
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

  private DecodedPkiMessage decode(CMSSignedData pkiMessage, PrivateKey recipientKey, X509Cert recipientCert)
      throws ScepClientException {
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
    if (bo != null && !bo) {
      throw new ScepClientException("Signature is invalid");
    }

    bo = resp.isDecryptionSuccessful();
    if (bo != null && !bo) {
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

  private static CMSSignedData parsePkiMessage(byte[] messageBytes) throws ScepClientException {
    try {
      return new CMSSignedData(messageBytes);
    } catch (CMSException ex) {
      throw new ScepClientException(ex);
    }
  }

  private static AuthorityCertStore retrieveCaCertStore(ScepHttpResponse resp, CaCertValidator caValidator)
      throws ScepClientException {
    String ct = resp.getContentType();

    X509Cert caCert = null;
    List<X509Cert> raCerts = new LinkedList<>();

    if (ScepConstants.CT_X509_CA_CERT.equalsIgnoreCase(ct)) {
      try {
        caCert = X509Util.parseCert(resp.getContentBytes());
      } catch (CertificateEncodingException ex) {
        throw new ScepClientException("error parsing certificate: " + ex.getMessage(), ex);
      }
    } else if (ScepConstants.CT_X509_CA_RA_CERT.equalsIgnoreCase(ct)) {
      ContentInfo contentInfo = ContentInfo.getInstance(resp.getContentBytes());

      SignedData signedData;
      try {
        signedData = SignedData.getInstance(contentInfo.getContent());
      } catch (IllegalArgumentException ex) {
        throw new ScepClientException("invalid SignedData message: " + ex.getMessage(), ex);
      }

      List<X509Cert> certs;
      try {
        certs = ScepUtil.getCertsFromSignedData(signedData);
      } catch (CertificateException ex) {
        throw new ScepClientException(ex.getMessage(), ex);
      }

      final int n = certs.size();
      if (n < 2) {
        throw new ScepClientException("at least 2 certificates are expected, but only " + n + " is available");
      }

      for (X509Cert cert : certs) {
        if (cert.getBasicConstraints() > -1) {
          if (caCert != null) {
            throw new ScepClientException("multiple CA certificates is returned, but exactly 1 is expected");
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
      throw new ScepClientException("CA certificate '" + caCert.getSubjectText() + "' is not trusted");
    }

    if (raCerts.isEmpty()) {
      return AuthorityCertStore.getInstance(caCert);
    }

    AuthorityCertStore cs = AuthorityCertStore.getInstance(caCert, raCerts.toArray(new X509Cert[0]));
    X509Cert raEncCert = cs.getEncryptionCert();
    X509Cert raSignCert = cs.getSignatureCert();
    try {
      if (!X509Util.issues(caCert, raEncCert)) {
        throw new ScepClientException("RA certificate '" + raEncCert.getSubjectText() + " is not issued by the CA");
      }
      if (raSignCert != raEncCert && X509Util.issues(caCert, raSignCert)) {
        throw new ScepClientException("RA certificate '" + raSignCert.getSubjectText() + " is not issued by the CA");
      }
    } catch (CertificateException ex) {
      throw new ScepClientException("invalid certificate: " + ex.getMessage(), ex);
    }

    return cs;
  } // method retrieveCaCertStore

  private static void assertSameNonce(PkiMessage request, PkiMessage response)
      throws ScepClientException {
    if (request.getSenderNonce().equals(response.getRecipientNonce())) {
      throw new ScepClientException("SenderNonce in request != RecipientNonce in response");
    }
  }

}
