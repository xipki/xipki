// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client.internal;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.CertificateConfirmationContent;
import org.bouncycastle.cert.cmp.CertificateConfirmationContentBuilder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.cmp.client.CmpClientException;
import org.xipki.cmp.client.EnrollCertRequest;
import org.xipki.cmp.client.PkiErrorException;
import org.xipki.cmp.client.Requestor;
import org.xipki.cmp.client.RevokeCertRequest;
import org.xipki.cmp.client.UnsuspendCertRequest;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.cmp.CmpUtf8Pairs;
import org.xipki.security.cmp.CmpUtil;
import org.xipki.security.cmp.ProtectionResult;
import org.xipki.security.cmp.ProtectionVerificationResult;
import org.xipki.security.cmp.VerifiedPkiMessage;
import org.xipki.security.encap.KemEncapKey;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.pkix.CrlReason;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.scep.util.XiDigestCalculatorProvider;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.util.Asn1Util;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;
import org.xipki.util.extra.http.HttpRespContent;
import org.xipki.util.extra.http.XiHttpClient;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.misc.ReqRespDebug;
import org.xipki.util.extra.misc.ReqRespDebug.ReqRespPair;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
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

  private static final int cmp2000 = 2;

  private static final int cmp2021 = 3;

  private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";

  private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

  private static final DigestCalculatorProvider DIGEST_CALCULATOR_PROVIDER
      = new XiDigestCalculatorProvider();

  private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);

  /**
   * Intern status to indicate that there are errors in the response.
   */
  protected static final int PKISTATUS_RESPONSE_ERROR = -1;

  protected static final int PKISTATUS_NO_ANSWER = -2;

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
    this.cmpVersion = Asn1Util.supportsCmpVersion(cmp2021) ? cmp2021 : cmp2000;
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
      } catch (CMPException | NoIdleSignerException ex) {
        throw new CmpClientException("could not sign the request", ex);
      }
    } else {
      Requestor.PbmMacCmpRequestor pbmRequestor = (Requestor.PbmMacCmpRequestor) requestor;

      try {
        return CmpUtil.addProtection(request, pbmRequestor.password(),
            pbmRequestor.parameter(), requestor.name(), pbmRequestor.senderKID());
      } catch (CMPException ex) {
        throw new CmpClientException("could not sign the request", ex);
      }
    }
  } // method sign

  private VerifiedPkiMessage signAndSend(
      String caName, Requestor requestor, Responder responder,
      PKIMessage request, ReqRespDebug debug)
      throws CmpClientException {
    ASN1OctetString tid = Args.notNull(request, "request").getHeader().getTransactionID();
    PKIMessage tmpRequest = sign(requestor, request);
    GeneralPKIMessage response = send(caName, tmpRequest, debug);

    GeneralName rec = response.getHeader().getRecipient();
    if (!requestor.name().equals(rec)) {
      LOG.warn("tid={}: unknown CMP requestor '{}'", tid, rec);
    }

    VerifiedPkiMessage ret = new VerifiedPkiMessage(response);
    if (response.hasProtection()) {
      try {
        ret.setProtectionVerificationResult(
            verifyProtection(requestor, responder, Hex.encode(tid.getOctets()), response));
      } catch (InvalidKeyException | CMPException ex) {
        throw new CmpClientException(ex.getMessage(), ex);
      }
    } else {
      if (response.getBody().getType() != PKIBody.TYPE_ERROR) {
        throw new CmpClientException("response is not signed");
      }
    }

    return ret;
  }

  private GeneralPKIMessage send(String caName, PKIMessage request, ReqRespDebug debug)
      throws CmpClientException {
    byte[] encodedRequest;
    try {
      encodedRequest = request.getEncoded();
    } catch (IOException ex) {
      LOG.error("could not encode the PKI request {}", request);
      throw new CmpClientException(ex.getMessage(), ex);
    }

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

    GeneralPKIMessage response;
    try {
      response = new GeneralPKIMessage(encodedResp);
    } catch (IOException ex) {
      LOG.error("could not decode the received PKI message: {}", Hex.encode(encodedResp));
      throw new CmpClientException(ex.getMessage(), ex);
    }

    PKIHeader reqHeader = request.getHeader();
    PKIHeader respHeader = response.getHeader();

    ASN1OctetString tid = reqHeader.getTransactionID();
    ASN1OctetString respTid = respHeader.getTransactionID();
    if (!tid.equals(respTid)) {
      LOG.warn("Response contains different tid ({}) than requested {}", respTid, tid);
      throw new CmpClientException("Response contains different tid than the request");
    }

    ASN1OctetString senderNonce = reqHeader.getSenderNonce();
    ASN1OctetString respRecipientNonce = respHeader.getRecipNonce();
    if (!senderNonce.equals(respRecipientNonce)) {
      LOG.warn("tid {}: response.recipientNonce ({}) != request.senderNonce ({})",
          tid, respRecipientNonce, senderNonce);
      throw new CmpClientException("Response contains differnt tid than the request");
    }

    return response;
  } // method send

  private PKIHeader buildPkiHeader(Requestor requestor, Responder responder) {
    return buildPkiHeader(requestor, responder,  false, null,
        null, (InfoTypeAndValue[]) null);
  }

  private PKIHeader buildPkiHeader(
      Requestor requestor, Responder responder, boolean addImplicitConfirm,
      ASN1OctetString tid, CmpUtf8Pairs utf8Pairs, InfoTypeAndValue... additionalGeneralInfos) {
    if (additionalGeneralInfos != null) {
      for (InfoTypeAndValue itv : additionalGeneralInfos) {
        if (itv == null) {
          continue;
        }

        ASN1ObjectIdentifier type = itv.getInfoType();
        if (OIDs.CMP.it_implicitConfirm.equals(type)) {
          throw new IllegalArgumentException(
              "additionGeneralInfos contains not-permitted ITV implicitConfirm");
        }

        if (OIDs.CMP.regInfo_utf8Pairs.equals(type)) {
          throw new IllegalArgumentException(
              "additionGeneralInfos contains not-permitted ITV utf8Pairs");
        }
      }
    }

    GeneralName sender = requestor != null ? requestor.name()
        : new GeneralName(new X500Name(new RDN[0]));

    GeneralName recipient = responder != null ? responder.name()
        : new GeneralName(new X500Name(new RDN[0]));

    PKIHeaderBuilder hdrBuilder = new PKIHeaderBuilder(cmpVersion, sender, recipient);

    hdrBuilder.setMessageTime(new ASN1GeneralizedTime(Date.from(Instant.now())));

    ASN1OctetString tmpTid = (tid == null) ? new DEROctetString(randomTransactionId()) : tid;

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
      hdrBuilder.setGeneralInfo(itvs.toArray(new InfoTypeAndValue[0]));
    }

    return hdrBuilder.build();
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
      Requestor requestor, Responder responder, String tid, GeneralPKIMessage pkiMessage)
      throws CMPException, InvalidKeyException {
    ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

    PKIHeader header = protectedMsg.getHeader();

    if (requestor instanceof Requestor.PbmMacCmpRequestor) {
      if (!protectedMsg.hasPasswordBasedMacProtection()) {
        LOG.warn("NOT_MAC_BASED: {}",
            pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
        return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      PBMParameter parameter = PBMParameter.getInstance(
          pkiMessage.getHeader().getProtectionAlg().getParameters());
      HashAlgo owf;
      try {
        owf = HashAlgo.getInstance(parameter.getOwf());
      } catch (NoSuchAlgorithmException ex) {
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

      PKMACBuilder pkMacBuilder = new PKMACBuilder(new JcePKMACValuesCalculator());

      boolean macValid = protectedMsg.verify(pkMacBuilder, macRequestor.password());
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
      if (header.getSender().getTagNo() != GeneralName.directoryName) {
        authorizedResponder = false;
      } else {
        X500Name msgSender = X500Name.getInstance(header.getSender().getName());
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

  private PKIMessage buildMessageWithGeneralMsgContent(ASN1ObjectIdentifier type) {
    InfoTypeAndValue itv = new InfoTypeAndValue(Args.notNull(type, "type"));
    PKIHeader header = buildPkiHeader(null, null);
    return new PKIMessage(header, new PKIBody(PKIBody.TYPE_GEN_MSG, new GenMsgContent(itv)));
  }

  X509CRLHolder downloadCurrentCrl(String caName, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    ASN1ObjectIdentifier type = OIDs.CMP.it_currentCRL;
    PKIMessage request = buildMessageWithGeneralMsgContent(type);

    GeneralPKIMessage response = send(caName, request, debug);
    ASN1Encodable itvValue = parseGenRep(response, type);
    return new X509CRLHolder(CertificateList.getInstance(itvValue));
  } // method downloadCrl

  List<X509Cert> caCerts(String caName, int maxNumCerts, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    ASN1ObjectIdentifier type = OIDs.CMP.id_it_caCerts;
    PKIMessage request = buildMessageWithGeneralMsgContent(type);

    GeneralPKIMessage response = send(caName, request, debug);
    ASN1Encodable itvValue = parseGenRep(response, type);
    ASN1Sequence seq = ASN1Sequence.getInstance(itvValue);
    int retSize = Math.min(maxNumCerts, seq.size());
    List<X509Cert> certs = new ArrayList<>(retSize);
    for (int i = 0; i < retSize; i++) {
      certs.add(new X509Cert(Certificate.getInstance(seq.getObjectAt(i))));
    }
    return certs;
  } // method caCerts

  KemEncapKey generateEncapKey(String caName, SubjectPublicKeyInfo publicKey, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    ASN1ObjectIdentifier type = OIDs.Xipki.id_xipki_cmp_kem_encapkey;

    InfoTypeAndValue itv;
    try {
      itv = new InfoTypeAndValue(Args.notNull(type, "type"),
              new DEROctetString(publicKey.getEncoded()));
    } catch (IOException e) {
      throw new CmpClientException("error encoding the publicKey");
    }

    PKIHeader header = buildPkiHeader(null, null);
    PKIMessage request = new PKIMessage(header,
        new PKIBody(PKIBody.TYPE_GEN_MSG, new GenMsgContent(itv)));

    GeneralPKIMessage response = send(caName, request, debug);
    ASN1Encodable itvValue = parseGenRep(response, type);
    return KemEncapKey.decode(ASN1OctetString.getInstance(itvValue).getOctets());
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
        reqIdIdMap, PKIBody.TYPE_CERT_REP, debug);
  } // method requestCertificate

  EnrollCertResponse requestCertificate(
      String caName, Requestor requestor, EnrollCertRequest req, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Responder responder = getResponder(requestor);
    PKIMessage request = buildPkiMessage(requestor, responder, Args.notNull(req, "req"));
    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    List<EnrollCertRequest.Entry> reqEntries = req.requestEntries();

    for (EnrollCertRequest.Entry reqEntry : reqEntries) {
      reqIdIdMap.put(reqEntry.certReq().getCertReqId().getValue(), reqEntry.id());
    }

    int exptectedBodyType;
    switch (req.type()) {
      case INIT_REQ:
        exptectedBodyType = PKIBody.TYPE_INIT_REP;
        break;
      case CERT_REQ:
        exptectedBodyType = PKIBody.TYPE_CERT_REP;
        break;
      case KEY_UPDATE:
        exptectedBodyType = PKIBody.TYPE_KEY_UPDATE_REP;
        break;
      case CROSS_CERT_REQ:
        exptectedBodyType = PKIBody.TYPE_CROSS_CERT_REP;
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
    final int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());

      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (expectedBodyType != bodyType) {
      throw new CmpClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, expectedBodyType, PKIBody.TYPE_ERROR));
    }

    CertRepMessage certRep = CertRepMessage.getInstance(respBody.getContent());
    CertResponse[] certResponses = certRep.getResponse();

    EnrollCertResponse result = new EnrollCertResponse();

    // CA certificates
    CMPCertificate[] caPubs = certRep.getCaPubs();
    if (caPubs != null) {
      for (CMPCertificate caPub : caPubs) {
        if (caPub != null) {
          result.addCaCertificate(caPub);
        }
      }
    }

    CertificateConfirmationContentBuilder certConfirmBuilder = null;
    if (!CmpUtil.isImplicitConfirm(response.pkiMessage().getHeader())) {
      certConfirmBuilder = new CertificateConfirmationContentBuilder();
    }
    boolean requireConfirm = false;

    // We only accept the certificates which are requested.
    for (CertResponse certResp : certResponses) {
      PKIStatusInfo statusInfo = certResp.getStatus();
      int status = statusInfo.getStatus().intValue();
      BigInteger certReqId = certResp.getCertReqId().getValue();
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
      if (status == PKIStatus.GRANTED || status == PKIStatus.GRANTED_WITH_MODS) {
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

        CmpCallbackImpl callback = new CmpCallbackImpl(requestor);
        byte[] decryptedPrivKey;
        try {
          decryptedPrivKey = KeyUtil.crmfDecryptEncryptedKey(cvk, callback);
        } catch (GeneralSecurityException ex) {
          LOG.warn("error decrypting CRMF private key", ex);
          result.addResultEntry(new ResultEntry.Error(thisId,
              PKISTATUS_RESPONSE_ERROR, PKIFailureInfo.systemFailure,
              "could not decrypt PrivateKeyInfo"));
          continue;
        }

        PrivateKeyInfo privateKeyInfo = null;
        if (decryptedPrivKey != null) {
          privateKeyInfo = PrivateKeyInfo.getInstance(decryptedPrivKey);
        }

        resultEntry = new ResultEntry.EnrollCert(thisId, cmpCert, privateKeyInfo, status);

        if (certConfirmBuilder != null) {
          requireConfirm = true;
          X509CertificateHolder certHolder = new X509CertificateHolder(cmpCert.getX509v3PKCert());
          certConfirmBuilder.addAcceptedCertificate(certHolder, certReqId);
        }
      } else {
        PKIFreeText statusString = statusInfo.getStatusString();
        String errorMessage = (statusString == null) ? null
            : Asn1Util.getTextAt(statusString, 0);

        int failureInfo = 0;
        if (statusInfo.getFailInfo() != null) {
          failureInfo = statusInfo.getFailInfo().intValue();
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
        response.pkiMessage().getHeader().getTransactionID(), certConfirmBuilder);

    response = signAndSend(caName, requestor, responder, confirmRequest, debug);
    checkProtection(response);

    return result;
  } // method requestCertificate0

  private PKIMessage buildCertConfirmRequest(
      Requestor requestor, Responder responder, ASN1OctetString tid,
      CertificateConfirmationContentBuilder certConfirmBuilder)
      throws CmpClientException {
    PKIHeader header = buildPkiHeader(requestor, responder, implicitConfirm,
        tid, null, (InfoTypeAndValue[]) null);

    CertificateConfirmationContent certConfirm;
    try {
      certConfirm = certConfirmBuilder.build(DIGEST_CALCULATOR_PROVIDER);
    } catch (CMPException ex) {
      throw new CmpClientException(ex.getMessage(), ex);
    }
    PKIBody body = new PKIBody(PKIBody.TYPE_CERT_CONFIRM, certConfirm.toASN1Structure());
    return new PKIMessage(header, body);
  } // method buildCertConfirmRequest

  private PKIMessage buildRevokeCertRequest(
      Requestor requestor, Responder responder, RevokeCertRequest request)
      throws CmpClientException {
    PKIHeader header = buildPkiHeader(requestor, responder);

    List<RevokeCertRequest.Entry> requestEntries = request.requestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (RevokeCertRequest.Entry requestEntry : requestEntries) {
      CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();
      certTempBuilder.setIssuer(requestEntry.issuer());
      certTempBuilder.setSerialNumber(new ASN1Integer(requestEntry.serialNumber()));
      byte[] aki = requestEntry.authorityKeyIdentifier();
      if (aki != null) {
        Extensions certTempExts = getCertTempExtensions(aki);
        certTempBuilder.setExtensions(certTempExts);
      }

      Instant invalidityDate = requestEntry.invalidityDate();
      int idx = (invalidityDate == null) ? 1 : 2;
      Extension[] extensions = new Extension[idx];

      try {
        ASN1Enumerated reason = new ASN1Enumerated(requestEntry.reason());
        extensions[0] = new Extension(OIDs.Extn.reasonCode, true,
                          new DEROctetString(reason.getEncoded()));

        if (invalidityDate != null) {
          ASN1GeneralizedTime time = new ASN1GeneralizedTime(Date.from(invalidityDate));
          extensions[1] = new Extension(OIDs.Extn.invalidityDate, true,
                            new DEROctetString(time.getEncoded()));
        }
      } catch (IOException ex) {
        throw new CmpClientException(ex.getMessage(), ex);
      }

      RevDetails revDetails = new RevDetails(certTempBuilder.build(), new Extensions(extensions));
      revDetailsArray.add(revDetails);
    }

    RevReqContent content = new RevReqContent(revDetailsArray.toArray(new RevDetails[0]));
    PKIBody body = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content);
    return new PKIMessage(header, body);
  } // method buildRevokeCertRequest

  private PKIMessage buildUnrevokeCertRequest(
      Requestor requestor, Responder responder, UnsuspendCertRequest request, int reasonCode)
      throws CmpClientException {
    PKIHeader header = buildPkiHeader(requestor, responder);

    List<UnsuspendCertRequest.Entry> requestEntries = request.requestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (UnsuspendCertRequest.Entry requestEntry : requestEntries) {
      CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();
      certTempBuilder.setIssuer(requestEntry.issuer());
      certTempBuilder.setSerialNumber(new ASN1Integer(requestEntry.serialNumber()));
      byte[] aki = requestEntry.authorityKeyIdentifier();
      if (aki != null) {
        Extensions certTempExts = getCertTempExtensions(aki);
        certTempBuilder.setExtensions(certTempExts);
      }

      Extension[] extensions = new Extension[1];

      try {
        ASN1Enumerated reason = new ASN1Enumerated(reasonCode);
        extensions[0] = new Extension(OIDs.Extn.reasonCode, true,
            new DEROctetString(reason.getEncoded()));
      } catch (IOException ex) {
        throw new CmpClientException(ex.getMessage(), ex);
      }
      Extensions exts = new Extensions(extensions);

      RevDetails revDetails = new RevDetails(certTempBuilder.build(), exts);
      revDetailsArray.add(revDetails);
    }

    RevReqContent content = new RevReqContent(revDetailsArray.toArray(new RevDetails[0]));
    return new PKIMessage(header, new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content));
  } // method buildUnrevokeOrRemoveCertRequest

  private PKIMessage buildPkiMessage(
      Requestor requestor, Responder responder,
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
      certProfileItv = new InfoTypeAndValue(OIDs.CMP.id_it_certProfile,
          new DERSequence(new DERUTF8String(csr.certprofile())));
    }

    PKIHeader header = buildPkiHeader(requestor, responder, implicitConfirm,
        null, utf8Pairs, certProfileItv);
    return new PKIMessage(header, new PKIBody(PKIBody.TYPE_P10_CERT_REQ, csr.csr()));
  } // method buildPkiMessage

  private PKIMessage buildPkiMessage(
      Requestor requestor, Responder responder, EnrollCertRequest req) {
    List<EnrollCertRequest.Entry> reqEntries = req.requestEntries();
    CertReqMsg[] certReqMsgs = new CertReqMsg[reqEntries.size()];

    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (int i = 0; i < reqEntries.size(); i++) {
      EnrollCertRequest.Entry reqEntry = reqEntries.get(i);

      if (reqEntry.certprofile() != null) {
        vec.add(new DERUTF8String(reqEntry.certprofile()));
      }

      certReqMsgs[i] = new CertReqMsg(reqEntry.certReq(), reqEntry.pop(), null);
    }

    if (vec.size() != 0 && vec.size() != reqEntries.size()) {
      throw new IllegalStateException("either not all reqEntries have CertProfile or all not" );
    }

    InfoTypeAndValue certProfile = new InfoTypeAndValue(
        OIDs.CMP.id_it_certProfile, new DERSequence(vec));

    PKIHeader header = buildPkiHeader(requestor, responder, implicitConfirm,
        null, null, certProfile);

    int bodyType;
    switch (req.type()) {
      case INIT_REQ:
        bodyType = PKIBody.TYPE_INIT_REQ;
        break;
      case CERT_REQ:
        bodyType = PKIBody.TYPE_CERT_REQ;
        break;
      case KEY_UPDATE:
        bodyType = PKIBody.TYPE_KEY_UPDATE_REQ;
        break;
      case CROSS_CERT_REQ:
        bodyType = PKIBody.TYPE_CROSS_CERT_REQ;
        break;
      default:
        throw new IllegalStateException("Unknown EnrollCertRequest.Type " + req.type());
    }

    return new PKIMessage(header, new PKIBody(bodyType, new CertReqMessages(certReqMsgs)));
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

  private static ASN1Encodable parseGenRep(
      GeneralPKIMessage response, ASN1ObjectIdentifier expectedType)
      throws CmpClientException, PkiErrorException {
    PKIBody respBody = response.getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());

      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (PKIBody.TYPE_GEN_REP != bodyType) {
      throw new CmpClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, PKIBody.TYPE_GEN_REP, PKIBody.TYPE_ERROR));
    }

    GenRepContent genRep = GenRepContent.getInstance(respBody.getContent());

    InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
    InfoTypeAndValue itv = null;
    if (itvs != null) {
      for (InfoTypeAndValue m : itvs) {
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
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());

      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (PKIBody.TYPE_REVOCATION_REP != bodyType) {
      throw new CmpClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, PKIBody.TYPE_REVOCATION_REP, PKIBody.TYPE_ERROR));
    }

    RevRepContent content = RevRepContent.getInstance(respBody.getContent());
    PKIStatusInfo[] statuses = content.getStatus();
    if (statuses == null || statuses.length != reqEntries.size()) {
      int statusesLen = 0;
      if (statuses != null) {
        statusesLen = statuses.length;
      }

      throw new CmpClientException(String.format(
          "incorrect number of status entries in response '%s' instead the expected '%s'",
          statusesLen, reqEntries.size()));
    }

    CertId[] revCerts = content.getRevCerts();

    RevokeCertResponse result = new RevokeCertResponse();
    for (int i = 0; i < statuses.length; i++) {
      PKIStatusInfo statusInfo = statuses[i];
      int status = statusInfo.getStatus().intValue();
      UnsuspendCertRequest.Entry re = reqEntries.get(i);

      if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
        PKIFreeText text = statusInfo.getStatusString();
        String statusString = (text == null) ? null : Asn1Util.getTextAt(text, 0);

        ResultEntry resultEntry = new ResultEntry.Error(re.id(), status,
            statusInfo.getFailInfo().intValue(), statusString);
        result.addResultEntry(resultEntry);
        continue;
      }

      CertId certId = null;
      if (revCerts != null) {
        for (CertId entry : revCerts) {
          if (re.issuer().equals(entry.getIssuer().getName())
              && re.serialNumber().equals(entry.getSerialNumber().getValue())) {
            certId = entry;
            break;
          }
        }
      }

      if (certId == null) {
        LOG.warn("certId is not present in response for (issuer='{}', serialNumber={})",
            X509Util.x500NameText(re.issuer()), LogUtil.formatCsn(re.serialNumber()));
        certId = new CertId(new GeneralName(re.issuer()), re.serialNumber());
      }

      result.addResultEntry(new ResultEntry.RevokeCert(re.id(), certId));
    }

    return result;
  } // method parse

  private static Extensions getCertTempExtensions(byte[] authorityKeyIdentifier)
      throws CmpClientException {
    AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(authorityKeyIdentifier);
    byte[] encodedAki;
    try {
      encodedAki = aki.getEncoded();
    } catch (IOException ex) {
      throw new CmpClientException("could not encoded AuthorityKeyIdentifier", ex);
    }
    return new Extensions(new Extension(OIDs.Extn.authorityKeyIdentifier, false, encodedAki));
  }

}
