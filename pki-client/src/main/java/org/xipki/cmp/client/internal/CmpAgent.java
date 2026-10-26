// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.internal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.pkix.asn1.cmp.*;
import org.xipki.pkix.asn1.cms.EnvelopedData;
import org.xipki.codec.asn1.crypto.GCMParameters;
import org.xipki.pkix.asn1.crmf.CertId;
import org.xipki.pkix.asn1.crmf.CertReqMessages;
import org.xipki.pkix.asn1.crmf.CertReqMsg;
import org.xipki.pkix.asn1.crmf.CertTemplate;
import org.xipki.pkix.asn1.crmf.EncryptedKey;
import org.xipki.pkix.asn1.crmf.EncryptedValue;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PBES2Parameters;
import org.xipki.codec.asn1.crypto.PBKDF2Params;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.RSAESOAEPParams;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.CmpOIDs;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.XipkiOIDs;
import org.xipki.pkix.asn1.util.ContentVerifierProvider;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.AuthorityKeyIdentifier;
import org.xipki.pkix.asn1.x509.CRLReason;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.CertificateList;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.asn1.x509.Extensions;
import org.xipki.pkix.asn1.x509.GeneralName;
import org.xipki.cmp.client.CmpClientException;
import org.xipki.cmp.client.EnrollCertRequest;
import org.xipki.cmp.client.PkiErrorException;
import org.xipki.cmp.client.Requestor;
import org.xipki.cmp.client.RevokeCertRequest;
import org.xipki.cmp.client.UnsuspendCertRequest;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.SecurityFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cmp.CmpException;
import org.xipki.pkix.cmp.CmpUtf8Pairs;
import org.xipki.pkix.cmp.CmpUtil;
import org.xipki.pkix.cmp.ProtectedPKIMessage;
import org.xipki.pkix.cmp.ProtectionResult;
import org.xipki.pkix.cmp.ProtectionVerificationResult;
import org.xipki.pkix.cmp.VerifiedPkiMessage;
import org.xipki.pkix.cms.CmsEnvelopedData;
import org.xipki.pkix.cms.CmsException;
import org.xipki.pkix.cms.CmsRecipient;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.pkix.exception.NoIdleSignerException;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.http.HttpRespContent;
import org.xipki.util.http.XiHttpClient;
import org.xipki.pkix.util.misc.CollectionUtil;
import org.xipki.util.misc.DateUtil;
import org.xipki.pkix.util.misc.LogUtil;
import org.xipki.util.http.ReqRespDebug;
import org.xipki.util.http.ReqRespDebug.ReqRespPair;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;

/**
 * CMP agent to communicate with CA.
 *
 * @author Lijun Liao (xipki)
 */
class CmpAgent {

  private static final Logger LOG = LoggerFactory.getLogger(CmpAgent.class);

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private static final int cmp2000 = 2;

  private static final int cmp2021 = 3;

  private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";

  private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

  private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);

  /**
   * Intern status to indicate that there are errors in the response.
   */
  protected static final PKIStatus PKISTATUS_RESPONSE_ERROR = PKIStatus.getInstance(-1);

  protected static final PKIStatus PKISTATUS_NO_ANSWER = PKIStatus.getInstance(-2);

  protected final SecurityFactory securityFactory;

  private final Random random = new Random();

  private final Responder pbmMacResponder;

  private final Responder signatureResponder;

  private final boolean sendRequestorCert;

  private final boolean implicitConfirm = true;

  private final XiHttpClient httpClient;

  private final String serverUrl;

  private final int cmpVersion;

  CmpAgent(Responder signatureResponder, Responder pbmMacResponder,
          String serverUrl, SecurityFactory securityFactory,
          SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier,
          boolean sendRequestorCert) {
    this.signatureResponder = signatureResponder;
    this.pbmMacResponder = pbmMacResponder;
    this.securityFactory = Args.notNull(securityFactory, "securityFactory");
    try {
      this.serverUrl = Args.notBlank(serverUrl, "serverUrl").endsWith("/")
          ? serverUrl : serverUrl + "/";

      new URL(this.serverUrl);
    } catch (MalformedURLException ex) {
      throw new IllegalArgumentException("invalid URL: " + serverUrl);
    }
    this.httpClient = new XiHttpClient(sslSocketFactory, hostnameVerifier);
    this.sendRequestorCert = sendRequestorCert;
    this.cmpVersion = cmp2021;
    LOG.info("Use CMP version {}", cmpVersion);
  } // constructor

  private Responder getResponder(Requestor requestor) {
    return (requestor instanceof Requestor.SignatureCmpRequestor)
        ? signatureResponder : pbmMacResponder;
  }

  private HttpRespContent send(String caName, byte[] request) throws IOException {
    Args.notNull(request, "request");
    return httpClient.httpPost(serverUrl + caName, CMP_REQUEST_MIMETYPE,
        request, CMP_RESPONSE_MIMETYPE);
  } // method send

  private PKIMessage sign(Requestor requestor, PKIMessage request) throws CmpClientException {
    Args.notNull(request, "request");
    if (requestor == null) {
      throw new CmpClientException("no request signer is configured");
    }

    if (requestor instanceof Requestor.SignatureCmpRequestor) {
      ConcurrentSigner signer = ((Requestor.SignatureCmpRequestor) requestor).signer();
      try {
        return CmpUtil.addProtection(request, signer, requestor.name(), sendRequestorCert);
      } catch (CmpException | NoIdleSignerException ex) {
        throw new CmpClientException("could not sign the request", ex);
      }
    } else {
      Requestor.PbmMacCmpRequestor pbmRequestor = (Requestor.PbmMacCmpRequestor) requestor;

      try {
        return CmpUtil.addProtection(request, pbmRequestor.password(),
            pbmRequestor.parameter(), requestor.name(), pbmRequestor.senderKID());
      } catch (CmpException ex) {
        throw new CmpClientException("could not sign the request", ex);
      }
    }
  } // method sign

  private VerifiedPkiMessage signAndSend(
      String caName, Requestor requestor, Responder responder,
      PKIMessage request, ReqRespDebug debug)
      throws CmpClientException {
    Asn1OctetString tid = Args.notNull(request, "request").getHeader().getTransactionID();
    PKIMessage tmpRequest = sign(requestor, request);
    PKIMessage response = send(caName, tmpRequest, debug);

    GeneralName rec = response.getHeader().getRecipient();
    if (!requestor.name().equals(rec)) {
      LOG.warn("tid={}: unknown CMP requestor '{}'", tid, rec);
    }

    VerifiedPkiMessage ret = new VerifiedPkiMessage(response);
    if (response.hasProtection()) {
      try {
        ret.setProtectionVerificationResult(
            verifyProtection(requestor, responder, Hex.encode(tid.getOctets()), response));
      } catch (InvalidKeyException | CmpException ex) {
        throw new CmpClientException(ex.getMessage(), ex);
      }
    } else {
      if (response.getBody().getTagNo() != PKIBody.tag_error) {
        throw new CmpClientException("response is not signed");
      }
    }

    return ret;
  }

  private PKIMessage send(String caName, PKIMessage request, ReqRespDebug debug)
      throws CmpClientException {
    byte[] encodedRequest = request.getEncoded();

    ReqRespPair reqResp = null;
    if (debug != null) {
      reqResp = new ReqRespPair();
      debug.add(reqResp);
      if (debug.saveRequest()) {
        reqResp.setRequest(encodedRequest);
      }
    }

    HttpRespContent resp;
    try {
      resp = send(caName, encodedRequest);
    } catch (IOException ex) {
      LogUtil.error(LOG, ex, "could not send the PKI request to server");
      throw new CmpClientException("TRANSPORT_ERROR", ex);
    }

    byte[] encodedResp = resp.content();
    if (reqResp != null && debug.saveResponse() && resp.content() != null) {
      reqResp.setResponse(encodedResp);
    }

    if (!resp.isOK()) {
      String msg = "received HTTP status code " + resp.statusCode();
      LOG.warn(msg);
      throw new CmpClientException(msg);
    }

    PKIMessage response;
    try {
      response = PKIMessage.fromEncoded(encodedResp);
    } catch (CodecException ex) {
      LOG.error("could not decode the received PKI message: {}", Hex.encode(encodedResp));
      throw new CmpClientException(ex.getMessage(), ex);
    }

    PKIHeader reqHeader = request.getHeader();
    PKIHeader respHeader = response.getHeader();

    Asn1OctetString tid = reqHeader.getTransactionID();
    Asn1OctetString respTid = respHeader.getTransactionID();
    if (!tid.equals(respTid)) {
      LOG.warn("Response contains different tid ({}) than requested {}", respTid, tid);
      throw new CmpClientException("Response contains different tid than the request");
    }

    Asn1OctetString senderNonce = reqHeader.getSenderNonce();
    Asn1OctetString respRecipientNonce = respHeader.getRecipNonce();
    if (!senderNonce.equals(respRecipientNonce)) {
      LOG.warn("tid {}: response.recipientNonce ({}) != request.senderNonce ({})",
          tid, respRecipientNonce, senderNonce);
      throw new CmpClientException("Response contains differnt tid than the request");
    }

    return response;
  } // method send

  private PKIHeader buildPkiHeader(Requestor requestor, Responder responder) {
    return buildPkiHeader(requestor, responder,  false, null, null, (InfoTypeAndValue[]) null);
  }

  private PKIHeader buildPkiHeader(
      Requestor requestor, Responder responder, boolean addImplicitConfirm,
      Asn1OctetString tid, CmpUtf8Pairs utf8Pairs, InfoTypeAndValue... additionalGeneralInfos) {
    if (additionalGeneralInfos != null) {
      for (InfoTypeAndValue itv : additionalGeneralInfos) {
        if (itv == null) {
          continue;
        }

        Asn1Oid type = itv.getInfoType();
        if (CmpOIDs.it_implicitConfirm.equals(type)) {
          throw new IllegalArgumentException(
              "additionGeneralInfos contains not-permitted ITV implicitConfirm");
        }

        if (CmpOIDs.id_regInfo_utf8Pairs.equals(type)) {
          throw new IllegalArgumentException(
              "additionGeneralInfos contains not-permitted ITV utf8Pairs");
        }
      }
    }

    GeneralName sender = requestor != null ? requestor.name()
        : GeneralName.ofDirectoryName(new X500Name());

    GeneralName recipient = responder != null ? responder.name()
        : GeneralName.ofDirectoryName(new X500Name());

    PKIHeader hdrBuilder = new PKIHeader(cmpVersion, sender, recipient);
    hdrBuilder.setMessageTime(new Asn1GeneralizedTime(Instant.now()));

    Asn1OctetString tmpTid = (tid == null) ? new Asn1OctetString(randomTransactionId()) : tid;

    hdrBuilder.setTransactionID(tmpTid);
    hdrBuilder.setSenderNonce(randomSenderNonce());

    List<InfoTypeAndValue> itvs = new ArrayList<>(2);
    if (addImplicitConfirm) {
      itvs.add(CmpUtil.getImplicitConfirmGeneralInfo());
    }

    if (utf8Pairs != null) {
      itvs.add(CmpUtil.buildInfoTypeAndValue(utf8Pairs));
    }

    if (additionalGeneralInfos != null) {
      for (InfoTypeAndValue itv : additionalGeneralInfos) {
        if (itv != null) {
          itvs.add(itv);
        }
      }
    }

    if (CollectionUtil.isNotEmpty(itvs)) {
      hdrBuilder.setGeneralInfo(new InfoTypeAndValue.Seq1(itvs));
    }

    return hdrBuilder;
  } // method buildPkiHeader

  private byte[] randomTransactionId() {
    byte[] tid = new byte[20];
    random.nextBytes(tid);
    return tid;
  }

  private byte[] randomSenderNonce() {
    byte[] bytes = new byte[16];
    random.nextBytes(bytes);
    return bytes;
  }

  private ProtectionVerificationResult verifyProtection(
      Requestor requestor, Responder responder, String tid, PKIMessage pkiMessage)
      throws CmpException, InvalidKeyException {
    ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

    PKIHeader header = protectedMsg.getHeader();

    if (requestor instanceof Requestor.PbmMacCmpRequestor) {
      if (!protectedMsg.hasPasswordBasedMacProtection()) {
        LOG.warn("NOT_MAC_BASED: {}",
            pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
        return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      PBMParameter parameter;
      HashAlgo owf;
      try {
        parameter = PBMParameter.fromAsn1(
            pkiMessage.getHeader().getProtectionAlg().getParameters().asSequence());
        owf = HashAlgo.getInstance(parameter.getOwf());
      } catch (NoSuchAlgorithmException | CodecException ex) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.owf)", ex);
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      Responder.PbmMacCmpResponder macResponder = (Responder.PbmMacCmpResponder) responder;

      if (!macResponder.isPbmOwfPermitted(owf)) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.owf: {})", owf);
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      SignAlgo mac;
      try {
        mac = SignAlgo.getInstance(parameter.getMac());
      } catch (NoSuchAlgorithmException ex) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.mac)", ex);
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      if (!macResponder.isPbmMacPermitted(mac)) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.mac: {})", mac);
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      Requestor.PbmMacCmpRequestor macRequestor = (Requestor.PbmMacCmpRequestor) requestor;

      boolean macValid = protectedMsg.verify(macRequestor.password());
      return new ProtectionVerificationResult(requestor,
          macValid ? ProtectionResult.MAC_VALID : ProtectionResult.MAC_INVALID);
    } else {
      if (protectedMsg.hasPasswordBasedMacProtection()) {
        LOG.warn("NOT_SIGNATURE_BASED: {}",
            pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
        return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      Responder.SignatureCmpResponder sigResponder = (Responder.SignatureCmpResponder) responder;
      boolean authorizedResponder;
      if (header.getSender().getTagNo() != GeneralName.tag_directoryName) {
        authorizedResponder = false;
      } else {
        X500Name msgSender = header.getSender().getDirectoryName();
        authorizedResponder = sigResponder.getCert().subject().equals(msgSender);
      }

      if (!authorizedResponder) {
        LOG.warn("tid={}: not authorized responder '{}'", tid, header.getSender());
        return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      SignAlgo protectionAlgo;
      try {
        protectionAlgo = SignAlgo.getInstance(protectedMsg.getHeader().getProtectionAlg());
      } catch (NoSuchAlgorithmException ex) {
        LOG.warn("tid={}: unknown response protection algorithm: {}", tid, ex.getMessage());
        return new ProtectionVerificationResult(null, ProtectionResult.SIGNATURE_INVALID);
      }

      if (protectionAlgo == null) {
        LOG.warn("tid={}: unknown response protection algorithm", tid);
        return new ProtectionVerificationResult(null, ProtectionResult.SIGNATURE_INVALID);
      }

      if (!sigResponder.getSigAlgoValidator()
          .isAlgorithmPermitted(protectionAlgo)) {
        LOG.warn("tid={}: response protected by untrusted protection algorithm '{}'",
            tid, protectionAlgo.jceName());
        return new ProtectionVerificationResult(null, ProtectionResult.SIGNATURE_INVALID);
      }

      X509Cert cert = sigResponder.getCert();
      ContentVerifierProvider verifierProvider = securityFactory.getContentVerifierProvider(cert);

      if (verifierProvider == null) {
        LOG.warn("tid={}: not authorized responder '{}'", tid, header.getSender());
        return new ProtectionVerificationResult(cert, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      boolean signatureValid = protectedMsg.verify(verifierProvider);
      return new ProtectionVerificationResult(cert,
          signatureValid ? ProtectionResult.SIGNATURE_VALID : ProtectionResult.SIGNATURE_INVALID);
    }
  } // method verifyProtection

  private PKIMessage buildMessageWithGeneralMsgContent(Asn1Oid type) {
    InfoTypeAndValue itv = new InfoTypeAndValue(Args.notNull(type, "type"), null);
    PKIHeader header = buildPkiHeader(null, null);
    return new PKIMessage(header, PKIBody.ofGenm(new GenMsgContent(itv)));
  }

  CertificateList downloadCurrentCrl(String caName, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Asn1Oid type = CmpOIDs.it_currentCRL;
    PKIMessage request = buildMessageWithGeneralMsgContent(type);

    PKIMessage response = send(caName, request, debug);
    Asn1Primitive itvValue = parseGenRep(response, type);
    try {
      return CertificateList.fromAsn1(itvValue.asSequence());
    } catch (CodecException e) {
      throw new CmpClientException("could not parse returned CRL", e);
    }
  } // method downloadCrl

  List<X509Cert> caCerts(String caName, int maxNumCerts, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Asn1Oid type = CmpOIDs.id_it_caCerts;
    PKIMessage request = buildMessageWithGeneralMsgContent(type);

    PKIMessage response = send(caName, request, debug);
    Asn1Primitive itvValue = parseGenRep(response, type);
    Asn1Sequence seq;
    try {
      seq = itvValue.asSequence();
    } catch (CodecException e) {
      throw new CmpClientException("could not parse returned CA certificates", e);
    }

    int retSize = Math.min(maxNumCerts, seq.size());
    List<X509Cert> certs = new ArrayList<>(retSize);

    for (int i = 0; i < retSize; i++) {
      try {
        certs.add(new X509Cert(Certificate.fromAsn1(seq.getSequenceAt(i))));
      } catch (CodecException e) {
        throw new CmpClientException("could not parse returned CA certificate at index " + i, e);
      }
    }
    return certs;
  } // method caCerts

  KemEncapKey generateEncapKey(
      String caName, Requestor requestor, SubjectPublicKeyInfo publicKey, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Asn1Oid type = XipkiOIDs.id_xipki_cmp_kem_encapkey;

    InfoTypeAndValue itv = new InfoTypeAndValue(Args.notNull(type, "type"),
        Asn1OctetString.wrap(publicKey));

    // the server requires an authenticated requestor
    Responder responder = getResponder(requestor);
    PKIHeader header = buildPkiHeader(requestor, responder);
    PKIMessage request = new PKIMessage(header, PKIBody.ofGenm(new GenMsgContent(itv)));

    VerifiedPkiMessage response = signAndSend(caName, requestor, responder, request, debug);
    checkProtection(response);
    Asn1Primitive itvValue = parseGenRep(response.pkiMessage(), type);
    return KemEncapKey.decode(((Asn1OctetString) itvValue).getOctets());
  } // method downloadCrl

  RevokeCertResponse revokeCertificate(
      String caName, Requestor requestor, RevokeCertRequest request, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Responder responder = getResponder(requestor);
    PKIMessage reqMessage = buildRevokeCertRequest(requestor, responder,
        Args.notNull(request, "request"));

    VerifiedPkiMessage response = signAndSend(caName, requestor, responder, reqMessage, debug);
    return parse(response, request.requestEntries());
  } // method revokeCertificate

  RevokeCertResponse unrevokeCertificate(
      String caName, Requestor requestor, UnsuspendCertRequest request, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Responder responder = getResponder(requestor);
    PKIMessage reqMessage = buildUnrevokeCertRequest(requestor, responder,
        Args.notNull(request, "request"), CrlReason.REMOVE_FROM_CRL.code());

    VerifiedPkiMessage response = signAndSend(caName, requestor, responder, reqMessage, debug);

    return parse(response, request.requestEntries());
  } // method unrevokeCertificate

  EnrollCertResponse requestCertificate(
      String caName, Requestor requestor, CsrEnrollCertRequest csr,
      Instant notBefore, Instant notAfter, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Responder responder = getResponder(requestor);
    PKIMessage request = buildPkiMessage(requestor, responder,
        Args.notNull(csr, "csr"), notBefore, notAfter);

    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    reqIdIdMap.put(MINUS_ONE, csr.id());
    return requestCertificate0(caName, requestor, responder, request,
        reqIdIdMap, PKIBody.tag_cp, debug);
  } // method requestCertificate

  EnrollCertResponse requestCertificate(
      String caName, Requestor requestor, EnrollCertRequest req, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Responder responder = getResponder(requestor);
    PKIMessage request = buildPkiMessage(requestor, responder, Args.notNull(req, "req"));
    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    List<EnrollCertRequest.Entry> reqEntries = req.requestEntries();

    for (EnrollCertRequest.Entry reqEntry : reqEntries) {
      reqIdIdMap.put(reqEntry.certReq().certReqId(), reqEntry.id());
    }

    int exptectedBodyType;
    switch (req.type()) {
      case INIT_REQ:
        exptectedBodyType = PKIBody.tag_ip;
        break;
      case CERT_REQ:
        exptectedBodyType = PKIBody.tag_cp;
        break;
      case KEY_UPDATE:
        exptectedBodyType = PKIBody.tag_kup;
        break;
      case CROSS_CERT_REQ:
        exptectedBodyType = PKIBody.tag_ccp;
        break;
      default:
        throw new IllegalStateException("unknown EnrollCertRequest.Type " + req.type());
    }

    return requestCertificate0(caName, requestor, responder,
        request, reqIdIdMap, exptectedBodyType, debug);
  } // method requestCertificate

  private EnrollCertResponse requestCertificate0(
      String caName, Requestor requestor, Responder responder,
      PKIMessage reqMessage, Map<BigInteger, String> reqIdIdMap,
      int expectedBodyType, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    VerifiedPkiMessage response = signAndSend(caName, requestor, responder, reqMessage, debug);
    checkProtection(response);

    PKIBody respBody = response.pkiMessage().getBody();
    final int bodyType = respBody.getTagNo();

    if (PKIBody.tag_error == bodyType) {
      ErrorMsgContent content = respBody.getError();

      throw new PkiErrorException(content.getPkiStatusInfo());
    } else if (expectedBodyType != bodyType) {
      throw new CmpClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, expectedBodyType, PKIBody.tag_error));
    }

    Asn1Encodable content = respBody.getChoiceData();
    CertRepMessage certRep;
    if (content instanceof CertRepMessage) {
      certRep = (CertRepMessage) content;
    } else {
      throw new CmpClientException(String.format(
          "invalid PKI body class %s for type %s", content.getClass().getName(), bodyType));
    }

    CertResponse.Seq0 certResponses = certRep.getResponse();

    EnrollCertResponse result = new EnrollCertResponse();

    // CA certificates
    CMPCertificate.Seq1 caPubs = certRep.getCaPubs();
    if (caPubs != null) {
      for (CMPCertificate caPub : caPubs) {
        if (caPub != null) {
          result.addCaCertificate(caPub);
        }
      }
    }

    List<CmpCertStatus> certConfirmEntries = null;
    if (!CmpUtil.isImplicitConfirm(response.pkiMessage().getHeader())) {
      certConfirmEntries = new ArrayList<>();
    }
    boolean requireConfirm = false;

    // We only accept the certificates which are requested.
    for (CertResponse certResp : certResponses) {
      PKIStatusInfo statusInfo = certResp.getStatus();
      PKIStatus status = statusInfo.getStatus();
      BigInteger certReqId = certResp.certReqId();
      String thisId = reqIdIdMap.get(certReqId);
      if (thisId != null) {
        reqIdIdMap.remove(certReqId);
      } else if (reqIdIdMap.size() == 1) {
        thisId = reqIdIdMap.values().iterator().next();
        reqIdIdMap.clear();
      }

      if (thisId == null) {
        continue; // ignore it. this cert is not requested by me
      }

      ResultEntry resultEntry;
      if (PKIStatus.accepted.equals(status) || PKIStatus.grantedWithMods.equals(status)) {
        CertifiedKeyPair cvk = certResp.getCertifiedKeyPair();
        if (cvk == null) {
          return null;
        }

        CMPCertificate cmpCert = cvk.getCertOrEncCert().getCertificate();
        if (cmpCert == null) {
          return null;
        }

        if (requestor == null) {
          result.addResultEntry(new ResultEntry.Error(thisId,
              PKISTATUS_RESPONSE_ERROR, PKIFailureInfo.systemFailure,
              "could not decrypt PrivateKeyInfo/requestor is null"));
          continue;
        }

        byte[] decryptedPrivKey;
        try {
          decryptedPrivKey = (cvk.getPrivateKey() == null) ? null
              : decryptPrivateKey(cvk.getPrivateKey(), requestor);
        } catch (GeneralSecurityException ex) {
          LOG.warn("error decrypting CRMF private key", ex);
          result.addResultEntry(new ResultEntry.Error(thisId,
              PKISTATUS_RESPONSE_ERROR, PKIFailureInfo.systemFailure,
              "could not decrypt PrivateKeyInfo"));
          continue;
        }

        PrivateKeyInfo privateKeyInfo = null;
        if (decryptedPrivKey != null) {
          try {
            privateKeyInfo = PrivateKeyInfo.fromEncoded(decryptedPrivKey);
          } catch (CodecException ex) {
            LOG.warn("error parsing decrypted CRMF private key", ex);
            result.addResultEntry(new ResultEntry.Error(thisId,
                PKISTATUS_RESPONSE_ERROR, PKIFailureInfo.systemFailure,
                "could not parse PrivateKeyInfo"));
            continue;
          }
        }

        resultEntry = new ResultEntry.EnrollCert(thisId, cmpCert, privateKeyInfo, status);

        if (certConfirmEntries != null) {
          requireConfirm = true;
          certConfirmEntries.add(new CmpCertStatus(
              certHash(cmpCert.getX509v3PKCert()), certReqId));
        }
      } else {
        PKIFreeText statusString = statusInfo.getStatusString();
        String errorMessage = (statusString == null) ? null
            : statusString.getStringAt(0);

        PKIFailureInfo failureInfo = null;
        if (statusInfo.getFailInfo() != null) {
          failureInfo = statusInfo.getFailInfo();
        }

        resultEntry = new ResultEntry.Error(thisId, status, failureInfo, errorMessage);
      }
      result.addResultEntry(resultEntry);
    }

    if (CollectionUtil.isNotEmpty(reqIdIdMap)) {
      for (Entry<BigInteger, String> entry : reqIdIdMap.entrySet()) {
        result.addResultEntry(new ResultEntry.Error(entry.getValue(), PKISTATUS_NO_ANSWER));
      }
    }

    if (!requireConfirm) {
      return result;
    }

    PKIMessage confirmRequest = buildCertConfirmRequest(requestor, responder,
        response.pkiMessage().getHeader().getTransactionID(), certConfirmEntries);

    response = signAndSend(caName, requestor, responder, confirmRequest, debug);
    checkProtection(response);

    return result;
  } // method requestCertificate0

  private PKIMessage buildCertConfirmRequest(
      Requestor requestor, Responder responder, Asn1OctetString tid,
      List<CmpCertStatus> certConfirmEntries) {
    PKIHeader header = buildPkiHeader(requestor, responder, implicitConfirm,
        tid, null, (InfoTypeAndValue[]) null);

    PKIBody body = PKIBody.ofCertConf(new CertConfirmContent(certConfirmEntries));
    return new PKIMessage(header, body);
  } // method buildCertConfirmRequest

  /**
   * Returns the certHash of the certificate in certConf, calculated with the hash algorithm
   * of the certificate's signature algorithm.
   */
  private static byte[] certHash(Certificate cert) throws CmpClientException {
    try {
      return SignAlgo.getHashAlgo(cert.getSignatureAlgorithm())
          .hash(cert.getEncoded());
    } catch (NoSuchAlgorithmException ex) {
      throw new CmpClientException("could not calculate the certHash: " + ex.getMessage(), ex);
    }
  }

  private PKIMessage buildRevokeCertRequest(
      Requestor requestor, Responder responder, RevokeCertRequest request) {
    PKIHeader header = buildPkiHeader(requestor, responder);

    List<RevokeCertRequest.Entry> requestEntries = request.requestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (RevokeCertRequest.Entry requestEntry : requestEntries) {
      CertTemplate certTempBuilder = new CertTemplate();
      certTempBuilder.setIssuer(requestEntry.issuer());
      certTempBuilder.setSerialNumber(new Asn1Integer(requestEntry.serialNumber()));
      byte[] aki = requestEntry.authorityKeyIdentifier();
      if (aki != null) {
        Extensions certTempExts = getCertTempExtensions(aki);
        certTempBuilder.setExtensions(certTempExts);
      }

      Instant invalidityDate = requestEntry.invalidityDate();
      int idx = (invalidityDate == null) ? 1 : 2;
      Extension[] extensions = new Extension[idx];

      CRLReason reason = CRLReason.getInstance(requestEntry.reason());
      extensions[0] = Extension.ofReasonCode(true, reason);

      if (invalidityDate != null) {
        extensions[1] = Extension.ofInvalidityDate(true, invalidityDate);
      }

      RevDetails revDetails = new RevDetails(certTempBuilder, new Extensions(extensions));
      revDetailsArray.add(revDetails);
    }

    RevReqContent content = new RevReqContent(revDetailsArray.toArray(new RevDetails[0]));
    PKIBody body = PKIBody.ofRr(content);
    return new PKIMessage(header, body);
  } // method buildRevokeCertRequest

  private PKIMessage buildUnrevokeCertRequest(
      Requestor requestor, Responder responder, UnsuspendCertRequest request, int reasonCode) {
    PKIHeader header = buildPkiHeader(requestor, responder);

    List<UnsuspendCertRequest.Entry> requestEntries = request.requestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (UnsuspendCertRequest.Entry requestEntry : requestEntries) {
      CertTemplate certTempBuilder = new CertTemplate();
      certTempBuilder.setIssuer(requestEntry.issuer());
      certTempBuilder.setSerialNumber(new Asn1Integer(requestEntry.serialNumber()));
      byte[] aki = requestEntry.authorityKeyIdentifier();
      if (aki != null) {
        Extensions certTempExts = getCertTempExtensions(aki);
        certTempBuilder.setExtensions(certTempExts);
      }

      Extension[] extensions = new Extension[1];

      extensions[0] = Extension.ofReasonCode(true, CRLReason.getInstance(reasonCode));

      Extensions exts = new Extensions(extensions);

      RevDetails revDetails = new RevDetails(certTempBuilder, exts);
      revDetailsArray.add(revDetails);
    }

    RevReqContent content = new RevReqContent(revDetailsArray.toArray(new RevDetails[0]));
    return new PKIMessage(header, PKIBody.ofRr(content));
  } // method buildUnrevokeOrRemoveCertRequest

  private PKIMessage buildPkiMessage(Requestor requestor, Responder responder,
      CsrEnrollCertRequest csr, Instant notBefore, Instant notAfter) {
    CmpUtf8Pairs utf8Pairs = null;
    if (notBefore != null) {
      utf8Pairs = new CmpUtf8Pairs();
      utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_NOTBEFORE,
          DateUtil.toUtcTimeyyyyMMddhhmmss(notBefore));
    }

    if (notAfter != null) {
      if (utf8Pairs == null) {
        utf8Pairs = new CmpUtf8Pairs();
      }
      utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_NOTAFTER, DateUtil.toUtcTimeyyyyMMddhhmmss(notAfter));
    }

    InfoTypeAndValue certProfileItv = null;
    if (csr.certprofile() != null) {
      certProfileItv = new InfoTypeAndValue(CmpOIDs.id_it_certProfile,
          new Asn1Sequence(new Asn1Utf8String(csr.certprofile())));
    }

    PKIHeader header = buildPkiHeader(requestor, responder, implicitConfirm,
        null, utf8Pairs, certProfileItv);
    return new PKIMessage(header, PKIBody.ofP10cr(csr.csr()));
  } // method buildPkiMessage

  private PKIMessage buildPkiMessage(
      Requestor requestor, Responder responder, EnrollCertRequest req) {
    List<EnrollCertRequest.Entry> reqEntries = req.requestEntries();
    CertReqMsg[] certReqMsgs = new CertReqMsg[reqEntries.size()];

    List<Asn1Encodable> vec = new LinkedList<>();
    for (int i = 0; i < reqEntries.size(); i++) {
      EnrollCertRequest.Entry reqEntry = reqEntries.get(i);

      if (reqEntry.certprofile() != null) {
        vec.add(new Asn1Utf8String(reqEntry.certprofile()));
      }

      certReqMsgs[i] = new CertReqMsg(reqEntry.certReq(), reqEntry.pop(), null);
    }

    if (!vec.isEmpty() && vec.size() != reqEntries.size()) {
      throw new IllegalStateException("either not all reqEntries have CertProfile or all not" );
    }

    InfoTypeAndValue certProfile = new InfoTypeAndValue(
        CmpOIDs.id_it_certProfile, new Asn1Sequence(vec));

    PKIHeader header = buildPkiHeader(requestor, responder, implicitConfirm,
        null, null, certProfile);

    CertReqMessages reqMsg = new CertReqMessages(certReqMsgs);
    PKIBody body;
    switch (req.type()) {
      case INIT_REQ:
        body = PKIBody.ofIr(reqMsg);
        break;
      case CERT_REQ:
        body = PKIBody.ofCr(reqMsg);
        break;
      case KEY_UPDATE:
        body = PKIBody.ofKur(reqMsg);
        break;
      case CROSS_CERT_REQ:
        body = PKIBody.ofCcr(reqMsg);
        break;
      default:
        throw new IllegalStateException("Unknown EnrollCertRequest.Type " + req.type());
    }

    return new PKIMessage(header, body);
  } // method buildPkiMessage

  private static void checkProtection(VerifiedPkiMessage response)
      throws PkiErrorException {
    if (!Args.notNull(response, "response").hasProtection()) {
      return;
    }

    ProtectionVerificationResult protectionVerificationResult =
        response.protectionVerificationResult();

    boolean valid;
    if (protectionVerificationResult == null) {
      valid = false;
    } else {
      ProtectionResult protectionResult =
          protectionVerificationResult.protectionResult();
      valid = protectionResult == ProtectionResult.MAC_VALID
          || protectionResult == ProtectionResult.SIGNATURE_VALID;
    }
    if (!valid) {
      throw new PkiErrorException(PKISTATUS_RESPONSE_ERROR,
          PKIFailureInfo.badMessageCheck, "message check of the response failed");
    }
  } // method checkProtection

  private static Asn1Primitive parseGenRep(
      PKIMessage response, Asn1Oid expectedType)
      throws CmpClientException, PkiErrorException {
    PKIBody respBody = response.getBody();
    int bodyType = respBody.getTagNo();

    if (PKIBody.tag_error == bodyType) {
      ErrorMsgContent content = respBody.getError();

      throw new PkiErrorException(content.getPkiStatusInfo());
    } else if (PKIBody.tag_genp != bodyType) {
      throw new CmpClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, PKIBody.tag_genp, PKIBody.tag_error));
    }

    GenRepContent genRep = respBody.getGenp();

    InfoTypeAndValue itv = null;
    if (genRep != null) {
      for (InfoTypeAndValue m : genRep) {
        if (expectedType.equals(m.getInfoType())) {
          itv = m;
          break;
        }
      }
    }

    if (itv == null) {
      throw new CmpClientException(
          "the response does not contain InfoTypeAndValue " + expectedType);
    }

    return itv.getInfoValue();
  } // method evaluateCrlResponse

  private static RevokeCertResponse parse(
      VerifiedPkiMessage response, List<? extends UnsuspendCertRequest.Entry> reqEntries)
      throws CmpClientException, PkiErrorException {
    checkProtection(Args.notNull(response, "response"));

    PKIBody respBody = response.pkiMessage().getBody();
    int bodyType = respBody.getTagNo();

    if (PKIBody.tag_error == bodyType) {
      ErrorMsgContent content = respBody.getError();
      throw new PkiErrorException(content.getPkiStatusInfo());
    } else if (PKIBody.tag_rp != bodyType) {
      throw new CmpClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, PKIBody.tag_rp, PKIBody.tag_error));
    }

    RevRepContent content = respBody.getRp();
    PKIStatusInfo.Seq1 statuses = content.getStatus();
    if (statuses == null || statuses.size() != reqEntries.size()) {
      int statusesLen = 0;
      if (statuses != null) {
        statusesLen = statuses.size();
      }

      throw new CmpClientException(String.format(
          "incorrect number of status entries in response '%s' instead the expected '%s'",
          statusesLen, reqEntries.size()));
    }

    CertId.Seq1 revCerts = content.getRevCerts();

    RevokeCertResponse result = new RevokeCertResponse();
    for (int i = 0; i < statuses.size(); i++) {
      PKIStatusInfo statusInfo = statuses.get(i);
      PKIStatus status = statusInfo.getStatus();
      UnsuspendCertRequest.Entry re = reqEntries.get(i);

      if (!PKIStatus.accepted.equals(status) && PKIStatus.grantedWithMods.equals(status)) {
        PKIFreeText text = statusInfo.getStatusString();
        String statusString = (text == null) ? null : text.getStringAt(0);

        ResultEntry resultEntry = new ResultEntry.Error(re.id(), status,
            statusInfo.getFailInfo(), statusString);
        result.addResultEntry(resultEntry);
        continue;
      }

      CertId certId = null;
      if (revCerts != null) {
        for (CertId entry : revCerts) {
          if (re.issuer().equals(entry.getIssuer().getDirectoryName())
              && re.serialNumber().equals(entry.serialNumber())) {
            certId = entry;
            break;
          }
        }
      }

      if (certId == null) {
        LOG.warn("certId is not present in response for (issuer='{}', serialNumber={})",
            X509Util.x500NameText(re.issuer()), LogUtil.formatCsn(re.serialNumber()));
        certId = new CertId(GeneralName.ofDirectoryName(re.issuer()), re.serialNumber());
      }

      result.addResultEntry(new ResultEntry.RevokeCert(re.id(), certId));
    }

    return result;
  } // method parse

  private static Extensions getCertTempExtensions(byte[] authorityKeyIdentifier) {
    AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(authorityKeyIdentifier);
    return new Extensions(Extension.ofAuthorityKeyIdentifier(false, aki));
  }

  /**
   * Decrypts the encrypted private key with the decryption key (signature requestor)
   * or the password (PBM requestor) of the requestor.
   */
  private static byte[] decryptPrivateKey(EncryptedKey encryptedKey, Requestor requestor)
      throws GeneralSecurityException {
    if (requestor instanceof Requestor.SignatureCmpRequestor) {
      ConcurrentSigner requestSigner = ((Requestor.SignatureCmpRequestor) requestor).signer();

      if (!(requestSigner.signingKey() instanceof PrivateKey)) {
        throw new GeneralSecurityException("no decryption key is configured");
      }

      return decrypt(encryptedKey, (PrivateKey) requestSigner.signingKey());
    } else {
      return decrypt(encryptedKey, ((Requestor.PbmMacCmpRequestor) requestor).password());
    }
  }

  private static byte[] decrypt(EncryptedKey ek, char[] password) throws GeneralSecurityException {
    if (ek.getEnvelopedData() != null) {
      return decrypt(ek.getEnvelopedData(), password);
    } else {
      return decrypt(ek.getEncryptedValue(), password);
    }
  }

  private static byte[] decrypt(EnvelopedData ed0, char[] password)
      throws GeneralSecurityException {
    try {
      for (CmsRecipient recipient : new CmsEnvelopedData(ed0).getRecipients()) {
        if (recipient.getType() == CmsRecipient.Type.PASSWORD) {
          return recipient.decrypt(password);
        }
      }
      throw new GeneralSecurityException("found no password recipient");
    } catch (CmsException ex) {
      throw new GeneralSecurityException(ex.getMessage(), ex);
    }
  }

  private static byte[] decrypt(EncryptedValue ev, char[] password)
      throws GeneralSecurityException {
    AlgorithmIdentifier symmAlg = ev.getSymmAlg();
    if (!AlgorithmOIDs.id_PBES2.equals(symmAlg.getAlgorithm())) {
      throw new GeneralSecurityException("unsupported symmAlg " + symmAlg.getAlgorithm().getId());
    }

    PBES2Parameters alg;
    try {
      alg = PBES2Parameters.fromAsn1(symmAlg.getParameters().asSequence());
    } catch (CodecException ex) {
      throw new GeneralSecurityException( "Error while parsing the PBES2Parameters", ex);
    }

    PBKDF2Params func;
    try {
      func = PBKDF2Params.fromAsn1(alg.getKeyDerivationFunc().getParameters().asSequence());
    } catch (CodecException ex) {
      throw new GeneralSecurityException( "Error while parsing the PBKDF2Params", ex);
    }

    AlgorithmIdentifier encScheme = alg.getEncryptionScheme();
    if (encScheme == null) {
      throw new GeneralSecurityException("unsupported symmAlg.parameters "
          + alg.getEncryptionScheme().getAlgorithm().getId());
    }

    try {
      if (!AlgorithmOIDs.id_PBKDF2.equals(alg.getKeyDerivationFunc().getAlgorithm())) {
        throw new GeneralSecurityException("unsupported key derivation function "
            + alg.getKeyDerivationFunc().getAlgorithm().getId());
      }

      int iterations = func.iterationCount();
      SecretKey key = new SecretKeySpec(cryptoApi.pbkdf2(func.getPrf(), password, func.salt(),
          iterations, aesGcmKeySize(encScheme) / 8), "AES");

      String cipherAlgOid = alg.getEncryptionScheme().getAlgorithm().getId();
      Cipher cipher = cryptoApi.newCipher(cipherAlgOid);

      Asn1Primitive encParams = alg.getEncryptionScheme().getParameters();
      GCMParameters gcmParameters = GCMParameters.fromAsn1(encParams.asSequence());
      GCMParameterSpec gcmParamSpec = new GCMParameterSpec(
          gcmParameters.icvLen() * 8, gcmParameters.nonce());

      cipher.init(Cipher.DECRYPT_MODE, key, gcmParamSpec);

      return cipher.doFinal(ev.encValue());
    } catch (GeneralSecurityException | CodecException ex) {
      throw new GeneralSecurityException( "Error while decrypting the EncryptedValue", ex);
    }
  } // method decrypt

  private static byte[] decrypt(EncryptedKey ek, PrivateKey decKey)
      throws GeneralSecurityException {
    if (ek.getEnvelopedData() != null) {
      return decrypt(ek.getEnvelopedData(), decKey);
    } else {
      return decrypt(ek.getEncryptedValue(), decKey);
    }
  }

  private static byte[] decrypt(EnvelopedData ed0, PrivateKey decKey)
      throws GeneralSecurityException {
    try {
      CmsRecipient recipient = new CmsEnvelopedData(ed0).getRecipients().get(0);
      if (recipient.getType() != CmsRecipient.Type.KEY_AGREE
          && recipient.getType() != CmsRecipient.Type.KEY_TRANS) {
        throw new GeneralSecurityException("unsupported recipient " + recipient.getType());
      }

      return recipient.decrypt(decKey);
    } catch (CmsException ex) {
      throw new GeneralSecurityException(ex.getMessage(), ex);
    }
  }

  private static byte[] decrypt(EncryptedValue ev, PrivateKey decKey)
      throws GeneralSecurityException {
    AlgorithmIdentifier keyAlg = ev.getKeyAlg();
    Asn1Oid keyOid = keyAlg.getAlgorithm();

    byte[] symmKey;
    try {
      if (decKey instanceof RSAPrivateKey) {
        Cipher keyCipher;
        if (keyOid.equals(AlgorithmOIDs.id_RSAES_OAEP)) {
          // Currently we only support the default RSAESOAEPparams
          if (keyAlg.getParameters() != null) {
            RSAESOAEPParams params = RSAESOAEPParams.fromAsn1(keyAlg.getParameters().asSequence());
            Asn1Oid oid = params.getHashAlgorithm().getAlgorithm();

            if (!oid.equals(RSAESOAEPParams.DEFAULT_HASH_ALGORITHM.getAlgorithm())) {
              throw new GeneralSecurityException(
                  "unsupported RSAESOAEPparams.HashAlgorithm " + oid.getId());
            }

            oid = params.getMaskGenAlgorithm().getAlgorithm();

            if (!oid.equals(RSAESOAEPParams.DEFAULT_MASK_GEN_FUNCTION.getAlgorithm())) {
              throw new GeneralSecurityException("unsupported " +
                  "RSAESOAEPparams.MaskGenAlgorithm " + oid.getId());
            }

            oid = params.getPSourceAlgorithm().getAlgorithm();
            if (!params.getPSourceAlgorithm().equals(RSAESOAEPParams.DEFAULT_P_SOURCE_ALGORITHM)) {
              throw new GeneralSecurityException(
                  "unsupported RSAESOAEPparams.PSourceAlgorithm " + oid.getId());
            }
          }

          keyCipher = cryptoApi.newCipher("RSA/NONE/OAEPPADDING");
        } else if (keyOid.equals(AlgorithmOIDs.id_rsaEncryption)) {
          keyCipher = cryptoApi.newCipher("RSA/NONE/PKCS1PADDING");
        } else {
          throw new GeneralSecurityException("unsupported keyAlg " + keyOid.getId());
        }
        keyCipher.init(Cipher.DECRYPT_MODE, decKey);

        symmKey = keyCipher.doFinal(ev.encSymmKey());
      } else if (decKey instanceof ECPrivateKey) {
        try {
          if (keyOid.equals(XipkiOIDs.id_alg_ECIES_hkdfsha256_aes256_gcm)) {
            symmKey = CmpUtil.unwrapCrmfContentEncryptionKey((ECPrivateKey) decKey, keyAlg, ev);
          } else {
            throw new GeneralSecurityException("unsupported keyAlg " + keyOid.getId());
          }
        } catch (XiSecurityException e) {
          throw new GeneralSecurityException(e);
        }
      } else {
        throw new GeneralSecurityException("unsupported decryption key type "
            + decKey.getClass().getName());
      }

      AlgorithmIdentifier symmAlg = ev.getSymmAlg();
      Asn1Oid symmAlgOid = symmAlg.getAlgorithm();
      if (!symmAlgOid.equals(AlgorithmOIDs.id_aes128_GCM)) {
        // currently we only support AES128-GCM
        throw new GeneralSecurityException("unsupported symmAlg " + symmAlgOid.getId());
      }
      GCMParameters params = GCMParameters.fromAsn1(symmAlg.getParameters().asSequence());
      Cipher dataCipher = cryptoApi.newCipher(symmAlgOid.getId());
      AlgorithmParameterSpec algParams =
          new GCMParameterSpec(params.icvLen() << 3, params.nonce());
      dataCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(symmKey, "AES"), algParams);

      byte[] encValue = ev.encValue();
      return dataCipher.doFinal(encValue);
    } catch (GeneralSecurityException | CodecException ex) {
      throw new GeneralSecurityException("Error while decrypting the EncryptedValue", ex);
    }
  } // method decrypt

  private static int aesGcmKeySize(AlgorithmIdentifier encScheme)
      throws GeneralSecurityException {
    Asn1Oid oid = encScheme.getAlgorithm();
    if (NistOIDs.id_aes128_GCM.equals(oid)) {
      return 128;
    } else if (NistOIDs.id_aes192_GCM.equals(oid)) {
      return 192;
    } else if (NistOIDs.id_aes256_GCM.equals(oid)) {
      return 256;
    } else {
      throw new GeneralSecurityException("unsupported encryption scheme " + oid.getId());
    }
  }

}
