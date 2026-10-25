// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.pkix.asn1.cms.ContentInfo;
import org.xipki.pkix.asn1.cms.IssuerAndSerialNumber;
import org.xipki.pkix.asn1.cms.SignedData;
import org.xipki.pkix.asn1.pkcs10.CertificationRequest;
import org.xipki.pkix.asn1.scep.IssuerAndSubject;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.CertificateList;
import org.xipki.codec.util.Args;
import org.xipki.codec.Base64;
import org.xipki.codec.exception.CodecException;
import org.xipki.pkix.cms.CmsAlgorithm;
import org.xipki.pkix.cms.CmsException;
import org.xipki.pkix.cms.CmsSignedData;
import org.xipki.scep.client.ScepClientException.OperationNotSupportedException;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.scep.message.AuthorityCertStore;
import org.xipki.pkix.scep.message.CaCaps;
import org.xipki.pkix.scep.message.DecodedNextCaMessage;
import org.xipki.pkix.scep.message.DecodedPkiMessage;
import org.xipki.pkix.scep.message.PkiMessage;
import org.xipki.pkix.scep.transaction.MessageType;
import org.xipki.pkix.scep.transaction.Operation;
import org.xipki.pkix.scep.transaction.PkiStatus;
import org.xipki.pkix.scep.transaction.TransactionId;
import org.xipki.pkix.scep.util.ScepUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.http.Curl;
import org.xipki.util.http.DefaultCurl;
import org.xipki.util.http.HttpStatusCode;
import org.xipki.pkix.util.misc.StringUtil;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * SCEP Client.
 *
 * @author Lijun Liao (xipki)
 */
public class ScepClient {

  public static final String REQ_CONTENT_TYPE = "application/octet-stream";

  // 5 minutes
  public static final long DEFAULT_SIGNINGTIME_BIAS = 5L * 60 * 1000;

  private final CaIdentifier caId;

  private CaCaps caCaps;

  private final CaCertValidator caCertValidator;

  private final Curl curl;

  private long maxSigningTimeBiasInMs = DEFAULT_SIGNINGTIME_BIAS;

  private AuthorityCertStore authorityCertStore;

  private List<Certificate> responseSignerCerts;

  private boolean httpGetOnly;

  public ScepClient(CaIdentifier caId, CaCertValidator caCertValidator) {
    this(caId, caCertValidator, null);
  }

  public ScepClient(CaIdentifier caId, CaCertValidator caCertValidator, Curl curl) {
    this.caId = Args.notNull(caId, "caId");
    this.caCertValidator = Args.notNull(caCertValidator, "caCertValidator");
    this.curl = curl == null ? new DefaultCurl() : curl;
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
  private ScepHttpResponse httpPost(String url, String requestContentType, byte[] request)
      throws ScepClientException {
    Curl.CurlResult resp;
    try {
      Map<String, String> headers = null;
      if (requestContentType != null) {
        headers = new HashMap<>();
        headers.put("content-type", requestContentType);
      }

      resp = curl.curlPost(url, false, headers, null, request);
    } catch (Exception ex) {
      throw new ScepClientException(ex);
    }
    return parseResp(resp);
  }

  /**
   * Send request via HTTP GET.
   *
   * @param url
   *          URL. Must not be {@code null}.
   * @return the response.
   * @throws ScepClientException
   *           If error occurs.
   */
  private ScepHttpResponse httpGet(String url) throws ScepClientException {
    Curl.CurlResult resp;
    try {
      resp = curl.curlGet(url, false, null, null);
    } catch (Exception ex) {
      throw new ScepClientException(ex);
    }
    return parseResp(resp);
  }

  public boolean isHttpGetOnly() {
    return httpGetOnly;
  }

  public void setHttpGetOnly(boolean httpGetOnly) {
    this.httpGetOnly = httpGetOnly;
  }

  public long maxSigningTimeBiasInMs() {
    return maxSigningTimeBiasInMs;
  }

  /**
   * Set the maximal signing time bias in milliseconds.
   * @param maxSigningTimeBiasInMs
   *        zero or negative value deactivates the message time check
   */
  public void setMaxSigningTimeBiasInMs(long maxSigningTimeBiasInMs) {
    this.maxSigningTimeBiasInMs = maxSigningTimeBiasInMs;
  }

  private ScepHttpResponse httpSend(Operation operation, ContentInfo pkiMessage)
      throws ScepClientException {
    byte[] request = null;
    if (pkiMessage != null) {
      request = pkiMessage.getEncoded();
    }

    if (Operation.GetCACaps == operation || Operation.GetCACert == operation
        || Operation.GetNextCACert == operation) {
      return httpGet(caId.buildGetUrl(operation, caId.profile()));
    } else {
      if (!httpGetOnly && caCaps.supportsPost()) {
        return httpPost(caId.buildPostUrl(operation), REQ_CONTENT_TYPE, request);
      } else {
        String url = caId.buildGetUrl(operation,
            (request == null) ? null : Base64.getEncoder().encodeToString(request));
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
    this.caCaps = CaCaps.getInstance(StringUtil.toUtf8String(getCaCapsResp.contentBytes()));

    // getCACert
    ScepHttpResponse getCaCertResp = httpSend(Operation.GetCACert);
    this.authorityCertStore = retrieveCaCertStore(getCaCertResp, caCertValidator);

    Certificate cert = this.authorityCertStore.signatureCert().getCert();
    this.responseSignerCerts = Collections.singletonList(cert);
  } // method refresh

  public CaCaps caCaps() throws ScepClientException {
    initIfNotInited();
    return caCaps;
  }

  public X509Cert caCert() {
    return authorityCertStore == null ? null : authorityCertStore.caCert();
  }

  public CaIdentifier caId() throws ScepClientException {
    initIfNotInited();
    return caId;
  }

  public CaCertValidator caCertValidator() throws ScepClientException {
    initIfNotInited();
    return caCertValidator;
  }

  public AuthorityCertStore authorityCertStore() throws ScepClientException {
    initIfNotInited();
    return authorityCertStore;
  }

  public CertificateList scepGetCrl(
      PrivateKey identityKey, X509Cert identityCert, X500Name issuer, BigInteger serialNumber)
      throws ScepClientException {
    Args.notNull(identityKey, "identityKey");
    Args.notNull(identityCert, "identityCert");
    Args.notNull(issuer, "issuer");
    Args.notNull(serialNumber, "serialNumber");

    initIfNotInited();

    PkiMessage pkiMessage = new PkiMessage(
        TransactionId.randomTransactionId(), MessageType.GetCRL);

    IssuerAndSerialNumber isn = new IssuerAndSerialNumber(issuer, serialNumber);
    pkiMessage.setMessageData(isn);
    ContentInfo request = encryptThenSign(pkiMessage, identityKey, identityCert);

    ScepHttpResponse httpResp = httpSend(Operation.PKIOperation, request);
    CmsSignedData cmsSignedData = parsePkiMessage(httpResp.contentBytes());
    PkiMessage response = decode(cmsSignedData, identityKey, identityCert);
    if (response.pkiStatus() != PkiStatus.SUCCESS) {
      throw new ScepClientException("server returned " + response.pkiStatus());
    }

    try {
      ContentInfo messageData = ContentInfo.fromAsn1(response.messageData().asSequence());

      return ScepUtil.getCrlFromPkiMessage(
          SignedData.fromAsn1(messageData.getContent().asSequence()));
    } catch (CodecException ex) {
      throw new ScepClientException(ex.getMessage(), ex);
    }
  }

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

    CmsSignedData cmsSignedData = parsePkiMessage(httpResp.contentBytes());
    DecodedPkiMessage response = decode(cmsSignedData, identityKey, identityCert);

    if (response.pkiStatus() != PkiStatus.SUCCESS) {
      throw new ScepClientException("server returned " + response.pkiStatus());
    }

    try {
      ContentInfo messageData = ContentInfo.fromAsn1(response.messageData().asSequence());
      return ScepUtil.getCertsFromSignedData(
          SignedData.fromAsn1(messageData.getContent().asSequence()));
    } catch (CertificateException | CodecException ex) {
      throw new ScepClientException(ex.getMessage(), ex);
    }
  }

  public EnrolmentResponse scepCertPoll(
      PrivateKey identityKey, X509Cert identityCert, CertificationRequest csr, X500Name issuer)
      throws ScepClientException {
    Args.notNull(csr, "csr");

    TransactionId tid = TransactionId.sha1TransactionId(csr.getSubjectPKInfo());

    return scepCertPoll(identityKey, identityCert, tid, issuer, csr.getSubject());
  }

  public EnrolmentResponse scepCertPoll(
      PrivateKey identityKey, X509Cert identityCert,
      TransactionId transactionId, X500Name issuer, X500Name subject)
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
    CmsSignedData cmsSignedData = parsePkiMessage(httpResp.contentBytes());
    DecodedPkiMessage response = decode(cmsSignedData, identityKey, identityCert);

    assertSameNonce(pkiMessage, response);
    return new EnrolmentResponse(response);
  }

  public EnrolmentResponse scepEnrol(
      CertificationRequest csr, PrivateKey identityKey, X509Cert identityCert)
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
  }

  public EnrolmentResponse scepPkcsReq(
      CertificationRequest csr, PrivateKey identityKey, X509Cert identityCert)
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

  public EnrolmentResponse scepRenewalReq(
      CertificationRequest csr, PrivateKey identityKey, X509Cert identityCert)
      throws ScepClientException {
    initIfNotInited();

    if (!caCaps.supportsRenewal()) {
      throw new OperationNotSupportedException(
          "unsupported messageType '" + MessageType.RenewalReq + "'");
    }

    if (identityCert.isSelfSigned()) {
      throw new IllegalArgumentException("identityCert must not be self-signed");
    }

    return enroll(MessageType.RenewalReq, csr, identityKey, identityCert);
  } // method scepRenewalReq

  private EnrolmentResponse enroll(
      MessageType messageType, CertificationRequest csr,
      PrivateKey identityKey, X509Cert identityCert)
      throws ScepClientException {
    TransactionId tid = TransactionId.sha1TransactionId(csr.getSubjectPKInfo());
    PkiMessage pkiMessage = new PkiMessage(tid, messageType);

    pkiMessage.setMessageData(csr);
    ContentInfo envRequest = encryptThenSign(pkiMessage, identityKey, identityCert);

    ScepHttpResponse httpResp = httpSend(Operation.PKIOperation, envRequest);

    CmsSignedData cmsSignedData = parsePkiMessage(httpResp.contentBytes());
    DecodedPkiMessage response = decode(cmsSignedData, identityKey, identityCert);

    assertSameNonce(pkiMessage, response);
    return new EnrolmentResponse(response);
  } // method enroll

  public AuthorityCertStore scepNextCaCert() throws ScepClientException {
    initIfNotInited();

    if (!this.caCaps.supportsGetNextCACert()) {
      throw new OperationNotSupportedException(
          "unsupported operation '" + Operation.GetNextCACert.code() + "'");
    }

    return retrieveNextCaAuthorityCertStore(httpSend(Operation.GetNextCACert));
  }

  private ContentInfo encryptThenSign(
      PkiMessage request, PrivateKey identityKey, X509Cert identityCert)
      throws ScepClientException {
    Asn1Oid encAlgId;
    if (caCaps.supportsAES()) {
      encAlgId = CmsAlgorithm.AES128_CBC;
    } else if (caCaps.supportsDES3()) {
      encAlgId = CmsAlgorithm.DES_EDE3_CBC;
    } else {
      throw new ScepClientException("DES will not be supported by this client");
    }

    try {
      SignAlgo signatureAlgorithm = SignAlgo.getInstance(identityKey);

      return request.encode(identityKey, signatureAlgorithm, identityCert,
          new X509Cert[]{identityCert}, authorityCertStore.encryptionCert(), encAlgId);
    } catch (CodecException | NoSuchAlgorithmException ex) {
      throw new ScepClientException(ex);
    }
  }

  private AuthorityCertStore retrieveNextCaAuthorityCertStore(ScepHttpResponse httpResp)
      throws ScepClientException {
    String ct = httpResp.contentType();

    if (!ScepUtil.CT_X509_NEXT_CA_CERT.equalsIgnoreCase(ct)) {
      throw new ScepClientException("invalid Content-Type '" + ct + "'");
    }

    CmsSignedData cmsSignedData;
    try {
      cmsSignedData = new CmsSignedData(httpResp.contentBytes());
    } catch (CmsException | IllegalArgumentException ex) {
      throw new ScepClientException("invalid SignedData message: " + ex.getMessage(), ex);
    }

    DecodedNextCaMessage resp;
    try {
      resp = DecodedNextCaMessage.decode(cmsSignedData, responseSignerCerts);
    } catch (CodecException ex) {
      throw new ScepClientException("could not decode response: " + ex.getMessage(), ex);
    }

    if (resp.failureMessage() != null) {
      throw new ScepClientException("Error: " + resp.failureMessage());
    }

    Boolean bo = resp.isSignatureValid();
    if (bo != null && !bo) {
      throw new ScepClientException("Signature is invalid");
    }

    Instant signingTime = resp.signingTime();
    long maxSigningTimeBias = maxSigningTimeBiasInMs();
    if (maxSigningTimeBias > 0) {
      if (signingTime == null) {
        throw new ScepClientException("CMS signingTime attribute is not present");
      }

      if (Math.abs(Instant.now().toEpochMilli() - signingTime.toEpochMilli())
          > maxSigningTimeBias) {
        throw new ScepClientException("CMS signingTime is out of permitted period");
      }
    }

    if (!resp.signatureCert().equals(authorityCertStore.signatureCert())) {
      throw new ScepClientException("the signature certificate must not be trusted");
    }

    return resp.authorityCertStore();
  }

  private void initIfNotInited() throws ScepClientException {
    if (caCaps == null) {
      init();
    }
  }

  private DecodedPkiMessage decode(
      CmsSignedData pkiMessage, PrivateKey recipientKey, X509Cert recipientCert)
      throws ScepClientException {
    DecodedPkiMessage resp;
    try {
      resp = DecodedPkiMessage.decode(pkiMessage, recipientKey, recipientCert, responseSignerCerts);
    } catch (CodecException ex) {
      throw new ScepClientException(ex);
    }

    if (resp.failureMessage() != null) {
      throw new ScepClientException("Error: " + resp.failureMessage());
    }

    Boolean bo = resp.isSignatureValid();
    if (bo != null && !bo) {
      throw new ScepClientException("Signature is invalid");
    }

    bo = resp.isDecryptionSuccessful();
    if (bo != null && !bo) {
      throw new ScepClientException("Decryption failed");
    }

    Instant signingTime = resp.signingTime();
    long maxSigningTimeBias = maxSigningTimeBiasInMs();
    if (maxSigningTimeBias > 0) {
      if (signingTime == null) {
        throw new ScepClientException("CMS signingTime attribute is not present");
      }

      if (Math.abs(Instant.now().toEpochMilli() - signingTime.toEpochMilli())
          > maxSigningTimeBias) {
        throw new ScepClientException("CMS signingTime is out of permitted period");
      }
    }

    if (!resp.signatureCert().equals(authorityCertStore.signatureCert())) {
      throw new ScepClientException("the signature certificate must not be trusted");
    }
    return resp;
  }

  private static CmsSignedData parsePkiMessage(byte[] messageBytes) throws ScepClientException {
    try {
      return new CmsSignedData(messageBytes);
    } catch (CmsException ex) {
      throw new ScepClientException(ex);
    }
  }

  private static AuthorityCertStore retrieveCaCertStore(
      ScepHttpResponse resp, CaCertValidator caValidator) throws ScepClientException {
    String ct = resp.contentType();

    X509Cert caCert = null;
    List<X509Cert> raCerts = new LinkedList<>();

    if (ScepUtil.CT_X509_CA_CERT.equalsIgnoreCase(ct)) {
      try {
        caCert = X509Util.parseCert(resp.contentBytes());
      } catch (CertificateEncodingException ex) {
        throw new ScepClientException("error parsing certificate: " + ex.getMessage(), ex);
      }
    } else if (ScepUtil.CT_X509_CA_RA_CERT.equalsIgnoreCase(ct)) {
      SignedData signedData;
      try {
        ContentInfo contentInfo = ContentInfo.fromEncoded(resp.contentBytes());
        signedData = SignedData.fromAsn1(contentInfo.getContent().asSequence());
      } catch (CodecException ex) {
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
        throw new ScepClientException("at least 2 certificates are expected, but only " +
            n + " is available");
      }

      for (X509Cert cert : certs) {
        if (cert.basicConstraints() > -1) {
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
      throw new ScepClientException("CA certificate '" + caCert.subjectText() + "' is not trusted");
    }

    if (raCerts.isEmpty()) {
      return AuthorityCertStore.getInstance(caCert);
    }

    AuthorityCertStore cs = AuthorityCertStore.getInstance(
        caCert, raCerts.toArray(new X509Cert[0]));
    X509Cert raEncCert = cs.encryptionCert();
    X509Cert raSignCert = cs.signatureCert();
    if (!X509Util.issues(caCert, raEncCert)) {
      throw new ScepClientException("RA certificate '" +
          raEncCert.subjectText() + "' is not issued by the CA");
    }
    if (raSignCert != raEncCert && !X509Util.issues(caCert, raSignCert)) {
      throw new ScepClientException("RA certificate '" +
          raSignCert.subjectText() + "' is not issued by the CA");
    }

    return cs;
  }

  private static void assertSameNonce(PkiMessage request, PkiMessage response)
      throws ScepClientException {
    if (request.senderNonce().equals(response.recipientNonce())) {
      throw new ScepClientException("SenderNonce in request != RecipientNonce in response");
    }
  }

  private static ScepHttpResponse parseResp(Curl.CurlResult resp) throws ScepClientException {
    int statusCode = resp.statusCode();
    if (statusCode != HttpStatusCode.SC_OK) {
      String msg = "server returned status code " + statusCode;
      byte[] errorContent = resp.errorContent();
      if (errorContent != null && errorContent.length != 0) {
        msg += ", message: " + new String(errorContent);
      }
      throw new ScepClientException(msg);
    }

    return new ScepHttpResponse(resp.contentType(), resp.content());
  }

}
