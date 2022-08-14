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

package org.xipki.cmpclient.internal;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.*;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.bc.BcPasswordEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.cmpclient.*;
import org.xipki.security.*;
import org.xipki.security.cmp.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.DateUtil;
import org.xipki.util.*;
import org.xipki.util.ReqRespDebug.ReqRespPair;
import org.xipki.util.http.HttpRespContent;
import org.xipki.util.http.XiHttpClient;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.Map.Entry;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * CMP agent to communicate with CA.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class CmpAgent {

  private static final Logger LOG = LoggerFactory.getLogger(CmpAgent.class);

  private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";

  private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

  private static final DefaultSecretKeySizeProvider KEYSIZE_PROVIDER =
      new DefaultSecretKeySizeProvider();

  private static final DigestCalculatorProvider DIGEST_CALCULATOR_PROVIDER =
      new BcDigestCalculatorProvider();

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

  CmpAgent(Responder signatureResponder, Responder pbmMacResponder,
           String serverUrl, SecurityFactory securityFactory,
           SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier,
           boolean sendRequestorCert) {
    this.signatureResponder = signatureResponder;
    this.pbmMacResponder = pbmMacResponder;
    this.securityFactory = notNull(securityFactory, "securityFactory");
    notBlank(serverUrl, "serverUrl");

    try {
      this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
      new URL(this.serverUrl);
    } catch (MalformedURLException ex) {
      throw new IllegalArgumentException("invalid URL: " + serverUrl);
    }
    this.httpClient = new XiHttpClient(sslSocketFactory, hostnameVerifier);
    this.sendRequestorCert = sendRequestorCert;
  } // constructor

  private Responder getResponder(Requestor requestor) {
    if (requestor instanceof Requestor.SignatureCmpRequestor) {
      return signatureResponder;
    } else {
      return pbmMacResponder;
    }
  }

  private HttpRespContent send(String caName, byte[] request)
      throws IOException {
    notNull(request, "request");
    return httpClient.httpPost(serverUrl + caName, CMP_REQUEST_MIMETYPE,
        request, CMP_RESPONSE_MIMETYPE);
  } // method send

  private PKIMessage sign(Requestor requestor, PKIMessage request)
      throws CmpClientException {
    notNull(request, "request");
    if (requestor == null) {
      throw new CmpClientException("no request signer is configured");
    }

    if (requestor instanceof Requestor.SignatureCmpRequestor) {
      ConcurrentContentSigner signer = ((Requestor.SignatureCmpRequestor) requestor).getSigner();
      try {
        return CmpUtil.addProtection(request, signer, requestor.getName(), sendRequestorCert);
      } catch (CMPException | NoIdleSignerException ex) {
        throw new CmpClientException("could not sign the request", ex);
      }
    } else {
      Requestor.PbmMacCmpRequestor pbmRequestor = (Requestor.PbmMacCmpRequestor) requestor;

      try {
        return CmpUtil.addProtection(request, pbmRequestor.getPassword(),
            pbmRequestor.getParameter(), requestor.getName(), pbmRequestor.getSenderKID());
      } catch (CMPException ex) {
        throw new CmpClientException("could not sign the request", ex);
      }
    }
  } // method sign

  private VerifiedPkiMessage signAndSend(
      String caName, Requestor requestor, Responder responder,
      PKIMessage request, ReqRespDebug debug)
      throws CmpClientException {
    ASN1OctetString tid = request.getHeader().getTransactionID();
    notNull(request, "request");
    PKIMessage tmpRequest = sign(requestor, request);
    GeneralPKIMessage response = send(caName, tmpRequest, debug);
    PKIHeader respHeader = response.getHeader();

    GeneralName rec = respHeader.getRecipient();
    if (!requestor.getName().equals(rec)) {
      LOG.warn("tid={}: unknown CMP requestor '{}'", tid, rec);
    }

    VerifiedPkiMessage ret = new VerifiedPkiMessage(response);
    if (response.hasProtection()) {
      try {
        ProtectionVerificationResult verifyProtection = verifyProtection(requestor,
            responder, Hex.encode(tid.getOctets()), response);
        ret.setProtectionVerificationResult(verifyProtection);
      } catch (InvalidKeyException | CMPException ex) {
        throw new CmpClientException(ex.getMessage(), ex);
      }
    } else {
      PKIBody respBody = response.getBody();
      int bodyType = respBody.getType();
      if (bodyType != PKIBody.TYPE_ERROR) {
        throw new CmpClientException("response is not signed");
      }
    }

    return ret;
  }

  private GeneralPKIMessage send(
      String caName, PKIMessage request, ReqRespDebug debug)
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

    byte[] encodedResp = resp.getContent();
    if (reqResp != null && debug.saveResponse() && resp.getContent() != null) {
      reqResp.setResponse(encodedResp);
    }

    if (!resp.isOK()) {
      String msg = "received HTTP status code " + resp.getStatusCode();
      LOG.warn(msg);
      throw new CmpClientException("Received HTTP status code");
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

  private PKIHeader buildPkiHeader(Requestor requestor, Responder responder, ASN1OctetString tid) {
    return buildPkiHeader(requestor, responder,  false, tid, null, (InfoTypeAndValue[]) null);
  }

  private PKIHeader buildPkiHeader(
      Requestor requestor, Responder responder,
      boolean addImplicitConfirm, ASN1OctetString tid,
      CmpUtf8Pairs utf8Pairs, InfoTypeAndValue... additionalGeneralInfos) {
    if (additionalGeneralInfos != null) {
      for (InfoTypeAndValue itv : additionalGeneralInfos) {
        if (itv == null) {
          continue;
        }

        ASN1ObjectIdentifier type = itv.getInfoType();
        if (CMPObjectIdentifiers.it_implicitConfirm.equals(type)) {
          throw new IllegalArgumentException(
              "additionGeneralInfos contains not-permitted ITV implicitConfirm");
        }

        if (CMPObjectIdentifiers.regInfo_utf8Pairs.equals(type)) {
          throw new IllegalArgumentException(
              "additionGeneralInfos contains not-permitted ITV utf8Pairs");
        }
      }
    }

    GeneralName sender = requestor != null ? requestor.getName()
        : new GeneralName(new X500Name(new RDN[0]));
    GeneralName recipient = responder != null ? responder.getName()
        : new GeneralName(new X500Name(new RDN[0]));

    PKIHeaderBuilder hdrBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, sender, recipient);
    hdrBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));

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

      Responder.PbmMacCmpResponder macResponder = (Responder.PbmMacCmpResponder) responder;
      PBMParameter parameter =
          PBMParameter.getInstance(pkiMessage.getHeader().getProtectionAlg().getParameters());
      HashAlgo owf;
      try {
        owf = HashAlgo.getInstance(parameter.getOwf());
      } catch (NoSuchAlgorithmException ex) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.owf)", ex);
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

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

      boolean macValid = protectedMsg.verify(pkMacBuilder, macRequestor.getPassword());
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
        authorizedResponder = sigResponder.getCert().getSubject().equals(msgSender);
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

      if (!sigResponder.getSigAlgoValidator().isAlgorithmPermitted(protectionAlgo)) {
        LOG.warn("tid={}: response protected by untrusted protection algorithm '{}'",
            tid, protectionAlgo.getJceName());
        return new ProtectionVerificationResult(null, ProtectionResult.SIGNATURE_INVALID);
      }

      X509Cert cert = sigResponder.getCert();
      ContentVerifierProvider verifierProvider = securityFactory.getContentVerifierProvider(cert);
      if (verifierProvider == null) {
        LOG.warn("tid={}: not authorized responder '{}'", tid, header.getSender());
        return new ProtectionVerificationResult(cert, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      boolean signatureValid = protectedMsg.verify(verifierProvider);
      return new ProtectionVerificationResult(cert, signatureValid
          ? ProtectionResult.SIGNATURE_VALID : ProtectionResult.SIGNATURE_INVALID);
    }
  } // method verifyProtection

  private PKIMessage buildMessageWithGeneralMsgContent(
      ASN1ObjectIdentifier type, ASN1Encodable value) {
    notNull(type, "type");

    PKIHeader header = buildPkiHeader(null, null, null);
    InfoTypeAndValue itv = (value != null) ? new InfoTypeAndValue(type, value)
        : new InfoTypeAndValue(type);
    GenMsgContent genMsgContent = new GenMsgContent(itv);
    PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);
    return new PKIMessage(header, body);
  } // method buildMessageWithGeneralMsgContent

  X509CRLHolder downloadCurrentCrl(String caName, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    ASN1ObjectIdentifier type = CMPObjectIdentifiers.it_currentCRL;
    PKIMessage request = buildMessageWithGeneralMsgContent(type, null);

    GeneralPKIMessage response = send(caName, request, debug);
    ASN1Encodable itvValue = parseGenRep(response, type);
    CertificateList certList = CertificateList.getInstance(itvValue);
    return new X509CRLHolder(certList);
  } // method downloadCrl

  List<X509Cert> caCerts(String caName, int maxNumCerts, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    ASN1ObjectIdentifier type = CMPObjectIdentifiers.id_it_caCerts;
    PKIMessage request = buildMessageWithGeneralMsgContent(type, null);

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

  RevokeCertResponse revokeCertificate(
      String caName, Requestor requestor, RevokeCertRequest request, ReqRespDebug debug)
          throws CmpClientException, PkiErrorException {
    Responder responder = getResponder(requestor);
    PKIMessage reqMessage = buildRevokeCertRequest(requestor, responder,
        notNull(request, "request"));
    VerifiedPkiMessage response = signAndSend(caName, requestor, responder, reqMessage, debug);
    return parse(response, request.getRequestEntries());
  } // method revokeCertificate

  RevokeCertResponse unrevokeCertificate(String caName,
      Requestor requestor, UnrevokeCertRequest request, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Responder responder = getResponder(requestor);
    PKIMessage reqMessage = buildUnrevokeCertRequest(
        requestor, responder, notNull(request, "request"),
        CrlReason.REMOVE_FROM_CRL.getCode());
    VerifiedPkiMessage response = signAndSend(caName, requestor, responder, reqMessage, debug);
    return parse(response, request.getRequestEntries());
  } // method unrevokeCertificate

  EnrollCertResponse requestCertificate(String caName,
      Requestor requestor, CsrEnrollCertRequest csr, Date notBefore,
      Date notAfter, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Responder responder = getResponder(requestor);
    PKIMessage request = buildPkiMessage(requestor, responder, notNull(csr, "csr"),
        notBefore, notAfter);
    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    reqIdIdMap.put(MINUS_ONE, csr.getId());
    return requestCertificate0(caName, requestor, responder, request, reqIdIdMap,
        PKIBody.TYPE_CERT_REP, debug);
  } // method requestCertificate

  EnrollCertResponse requestCertificate(
      String caName,  Requestor requestor, EnrollCertRequest req, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Responder responder = getResponder(requestor);
    PKIMessage request = buildPkiMessage(requestor, responder, notNull(req, "req"));
    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    List<EnrollCertRequest.Entry> reqEntries = req.getRequestEntries();

    for (EnrollCertRequest.Entry reqEntry : reqEntries) {
      reqIdIdMap.put(reqEntry.getCertReq().getCertReqId().getValue(), reqEntry.getId());
    }

    int exptectedBodyType;
    switch (req.getType()) {
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
        throw new IllegalStateException("unknown EnrollCertRequest.Type " + req.getType());
    }

    return requestCertificate0(caName, requestor, responder, request, reqIdIdMap,
        exptectedBodyType, debug);
  } // method requestCertificate

  private EnrollCertResponse requestCertificate0(
      String caName, Requestor requestor, Responder responder, PKIMessage reqMessage,
      Map<BigInteger, String> reqIdIdMap, int expectedBodyType, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    VerifiedPkiMessage response = signAndSend(caName, requestor, responder, reqMessage, debug);
    checkProtection(response);

    PKIBody respBody = response.getPkiMessage().getBody();
    final int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (expectedBodyType != bodyType) {
      throw new CmpClientException(String.format(
              "unknown PKI body type %s instead the expected [%s, %s]", bodyType,
              expectedBodyType, PKIBody.TYPE_ERROR));
    }

    CertRepMessage certRep = CertRepMessage.getInstance(respBody.getContent());
    CertResponse[] certResponses = certRep.getResponse();

    EnrollCertResponse result = new EnrollCertResponse();

    // CA certificates
    CMPCertificate[] caPubs = certRep.getCaPubs();
    if (caPubs != null && caPubs.length > 0) {
      for (CMPCertificate caPub : caPubs) {
        if (caPub != null) {
          result.addCaCertificate(caPub);
        }
      }
    }

    CertificateConfirmationContentBuilder certConfirmBuilder = null;
    if (!CmpUtil.isImplicitConfirm(response.getPkiMessage().getHeader())) {
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
          result.addResultEntry(new ResultEntry.Error(thisId, PKISTATUS_RESPONSE_ERROR,
              PKIFailureInfo.systemFailure,"could not decrypt PrivateKeyInfo/requestor is null"));
          continue;
        }

        PrivateKeyInfo privKeyInfo = null;
        if (cvk.getPrivateKey() != null) {
          // decryp the encrypted private key
          byte[] decryptedValue;
          try {
            if (requestor instanceof Requestor.SignatureCmpRequestor) {
              ConcurrentContentSigner requestSigner =
                  ((Requestor.SignatureCmpRequestor) requestor).getSigner();
              if (!(requestSigner.getSigningKey() instanceof PrivateKey)) {
                throw new XiSecurityException("no decryption key is configured");
              }

              decryptedValue = decrypt(cvk.getPrivateKey(),
                  (PrivateKey) requestSigner.getSigningKey());
            } else {
              decryptedValue = decrypt(cvk.getPrivateKey(),
                  ((Requestor.PbmMacCmpRequestor) requestor).getPassword());
            }
          } catch (XiSecurityException ex) {
            result.addResultEntry(new ResultEntry.Error(thisId, PKISTATUS_RESPONSE_ERROR,
                PKIFailureInfo.systemFailure, "could not decrypt PrivateKeyInfo"));
            continue;
          }
          privKeyInfo = PrivateKeyInfo.getInstance(decryptedValue);
        }

        resultEntry = new ResultEntry.EnrollCert(thisId, cmpCert, privKeyInfo, status);

        if (certConfirmBuilder != null) {
          requireConfirm = true;
          X509CertificateHolder certHolder = new X509CertificateHolder(cmpCert.getX509v3PKCert());
          certConfirmBuilder.addAcceptedCertificate(certHolder, certReqId);
        }
      } else {
        PKIFreeText statusString = statusInfo.getStatusString();
        String errorMessage = (statusString == null)
            ? null : statusString.getStringAt(0).getString();
        int failureInfo = statusInfo.getFailInfo().intValue();

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
        response.getPkiMessage().getHeader().getTransactionID(), certConfirmBuilder);

    response = signAndSend(caName, requestor, responder, confirmRequest, debug);
    checkProtection(response);

    return result;
  } // method requestCertificate0

  private PKIMessage buildCertConfirmRequest(
      Requestor requestor, Responder responder, ASN1OctetString tid,
      CertificateConfirmationContentBuilder certConfirmBuilder)
          throws CmpClientException {
    PKIHeader header = buildPkiHeader(requestor, responder, implicitConfirm, tid, null,
        (InfoTypeAndValue[]) null);
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
    PKIHeader header = buildPkiHeader(requestor, responder, null);

    List<RevokeCertRequest.Entry> requestEntries = request.getRequestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (RevokeCertRequest.Entry requestEntry : requestEntries) {
      CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();
      certTempBuilder.setIssuer(requestEntry.getIssuer());
      certTempBuilder.setSerialNumber(new ASN1Integer(requestEntry.getSerialNumber()));
      byte[] aki = requestEntry.getAuthorityKeyIdentifier();
      if (aki != null) {
        Extensions certTempExts = getCertTempExtensions(aki);
        certTempBuilder.setExtensions(certTempExts);
      }

      Date invalidityDate = requestEntry.getInvalidityDate();
      int idx = (invalidityDate == null) ? 1 : 2;
      Extension[] extensions = new Extension[idx];

      try {
        ASN1Enumerated reason = new ASN1Enumerated(requestEntry.getReason());
        extensions[0] = new Extension(Extension.reasonCode, true,
            new DEROctetString(reason.getEncoded()));

        if (invalidityDate != null) {
          ASN1GeneralizedTime time = new ASN1GeneralizedTime(invalidityDate);
          extensions[1] = new Extension(Extension.invalidityDate, true,
                  new DEROctetString(time.getEncoded()));
        }
      } catch (IOException ex) {
        throw new CmpClientException(ex.getMessage(), ex);
      }

      Extensions exts = new Extensions(extensions);

      RevDetails revDetails = new RevDetails(certTempBuilder.build(), exts);
      revDetailsArray.add(revDetails);
    }

    RevReqContent content = new RevReqContent(revDetailsArray.toArray(new RevDetails[0]));
    PKIBody body = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content);
    return new PKIMessage(header, body);
  } // method buildRevokeCertRequest

  private PKIMessage buildUnrevokeCertRequest(
      Requestor requestor, Responder responder, UnrevokeCertRequest request, int reasonCode)
          throws CmpClientException {
    PKIHeader header = buildPkiHeader(requestor, responder, null);

    List<UnrevokeCertRequest.Entry> requestEntries = request.getRequestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (UnrevokeCertRequest.Entry requestEntry : requestEntries) {
      CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();
      certTempBuilder.setIssuer(requestEntry.getIssuer());
      certTempBuilder.setSerialNumber(new ASN1Integer(requestEntry.getSerialNumber()));
      byte[] aki = requestEntry.getAuthorityKeyIdentifier();
      if (aki != null) {
        Extensions certTempExts = getCertTempExtensions(aki);
        certTempBuilder.setExtensions(certTempExts);
      }

      Extension[] extensions = new Extension[1];

      try {
        ASN1Enumerated reason = new ASN1Enumerated(reasonCode);
        extensions[0] = new Extension(Extension.reasonCode, true,
                new DEROctetString(reason.getEncoded()));
      } catch (IOException ex) {
        throw new CmpClientException(ex.getMessage(), ex);
      }
      Extensions exts = new Extensions(extensions);

      RevDetails revDetails = new RevDetails(certTempBuilder.build(), exts);
      revDetailsArray.add(revDetails);
    }

    RevReqContent content = new RevReqContent(revDetailsArray.toArray(new RevDetails[0]));
    PKIBody body = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, content);
    return new PKIMessage(header, body);
  } // method buildUnrevokeOrRemoveCertRequest

  private PKIMessage buildPkiMessage(
      Requestor requestor, Responder responder,
      CsrEnrollCertRequest csr, Date notBefore, Date notAfter) {
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
    if (csr.getCertprofile() != null) {
      certProfileItv = new InfoTypeAndValue(
              ObjectIdentifiers.CMP.id_it_certProfile,
              new DERSequence(new DERUTF8String(csr.getCertprofile())));
    }

    PKIHeader header = buildPkiHeader(requestor, responder, implicitConfirm, null,
        utf8Pairs, certProfileItv);
    PKIBody body = new PKIBody(PKIBody.TYPE_P10_CERT_REQ, csr.getCsr());

    return new PKIMessage(header, body);
  } // method buildPkiMessage

  private PKIMessage buildPkiMessage(
      Requestor requestor, Responder responder, EnrollCertRequest req) {
    List<EnrollCertRequest.Entry> reqEntries = req.getRequestEntries();
    CertReqMsg[] certReqMsgs = new CertReqMsg[reqEntries.size()];

    ASN1EncodableVector vec = new ASN1EncodableVector();

    for (int i = 0; i < reqEntries.size(); i++) {
      EnrollCertRequest.Entry reqEntry = reqEntries.get(i);

      if (reqEntry.getCertprofile() != null) {
        vec.add(new DERUTF8String(reqEntry.getCertprofile()));
      }

      certReqMsgs[i] = new CertReqMsg(reqEntry.getCertReq(), reqEntry.getPop(), null);
    }

    if (vec.size() != 0 && vec.size() != reqEntries.size()) {
      throw new IllegalStateException("either not all reqEntries have CertProfile or all not" );
    }

    InfoTypeAndValue certProfile = new InfoTypeAndValue(
                    ObjectIdentifiers.CMP.id_it_certProfile, new DERSequence(vec));
    PKIHeader header = buildPkiHeader(requestor, responder, implicitConfirm, null, null,
        certProfile);

    int bodyType;
    switch (req.getType()) {
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
        throw new IllegalStateException("Unknown EnrollCertRequest.Type " + req.getType());
    }

    PKIBody body = new PKIBody(bodyType, new CertReqMessages(certReqMsgs));
    return new PKIMessage(header, body);
  } // method buildPkiMessage

  private static void checkProtection(VerifiedPkiMessage response)
      throws PkiErrorException {
    notNull(response, "response");

    if (!response.hasProtection()) {
      return;
    }

    ProtectionVerificationResult protectionVerificationResult =
        response.getProtectionVerificationResult();

    boolean valid;
    if (protectionVerificationResult == null) {
      valid = false;
    } else {
      ProtectionResult protectionResult = protectionVerificationResult.getProtectionResult();
      valid = protectionResult == ProtectionResult.MAC_VALID
          || protectionResult == ProtectionResult.SIGNATURE_VALID;
    }
    if (!valid) {
      throw new PkiErrorException(PKISTATUS_RESPONSE_ERROR,
          PKIFailureInfo.badMessageCheck, "message check of the response failed");
    }
  } // method checkProtection

  private static byte[] decrypt(EncryptedKey ek, char[] password)
      throws XiSecurityException {
    ASN1Encodable ekValue = ek.getValue();
    if (ekValue instanceof EnvelopedData) {
      return decrypt((EnvelopedData) ekValue, password);
    } else {
      return decrypt((EncryptedValue) ekValue, password);
    }
  }

  private static byte[] decrypt(EnvelopedData ed0, char[] password)
      throws XiSecurityException {
    try {
      ContentInfo ci = new ContentInfo(CMSObjectIdentifiers.envelopedData, ed0);
      CMSEnvelopedData ed = new CMSEnvelopedData(ci);

      RecipientInformationStore recipients = ed.getRecipientInfos();
      Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
      PasswordRecipientInformation recipient = (PasswordRecipientInformation) it.next();

      return recipient.getContent(new BcPasswordEnvelopedRecipient(password));
    } catch (CMSException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  }

  private static byte[] decrypt(EncryptedValue ev, char[] password)
      throws XiSecurityException {
    AlgorithmIdentifier symmAlg = ev.getSymmAlg();
    if (!PKCSObjectIdentifiers.id_PBES2.equals(symmAlg.getAlgorithm())) {
      throw new XiSecurityException("unsupported symmAlg " + symmAlg.getAlgorithm().getId());
    }

    PBES2Parameters alg = PBES2Parameters.getInstance(symmAlg.getParameters());
    PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
    AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

    try {
      SecretKeyFactory keyFact =
          SecretKeyFactory.getInstance(alg.getKeyDerivationFunc().getAlgorithm().getId());
      SecretKey key;

      int iterations = func.getIterationCount().intValue();
      key = keyFact.generateSecret(new PBKDF2KeySpec(password, func.getSalt(), iterations,
          KEYSIZE_PROVIDER.getKeySize(encScheme), func.getPrf()));
      key = new SecretKeySpec(key.getEncoded(), "AES");

      String cipherAlgOid = alg.getEncryptionScheme().getAlgorithm().getId();
      Cipher cipher = Cipher.getInstance(cipherAlgOid);

      ASN1Encodable encParams = alg.getEncryptionScheme().getParameters();
      GCMParameters gcmParameters = GCMParameters.getInstance(encParams);
      GCMParameterSpec gcmParamSpec =
          new GCMParameterSpec(gcmParameters.getIcvLen() * 8, gcmParameters.getNonce());
      cipher.init(Cipher.DECRYPT_MODE, key, gcmParamSpec);

      return cipher.doFinal(ev.getEncValue().getOctets());
    } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
             | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException
             | InvalidAlgorithmParameterException ex) {
      throw new XiSecurityException("Error while decrypting the EncryptedValue", ex);
    }
  } // method decrypt

  private static byte[] decrypt(EncryptedKey ek, PrivateKey decKey)
      throws XiSecurityException {
    ASN1Encodable ekValue = ek.getValue();
    if (ekValue instanceof EnvelopedData) {
      return decrypt((EnvelopedData) ekValue, decKey);
    } else {
      return decrypt((EncryptedValue) ekValue, decKey);
    }
  }

  private static byte[] decrypt(EnvelopedData ed0, PrivateKey decKey)
      throws XiSecurityException {
    try {
      ContentInfo ci = new ContentInfo(CMSObjectIdentifiers.envelopedData, ed0);
      CMSEnvelopedData ed = new CMSEnvelopedData(ci);

      RecipientInformationStore recipients = ed.getRecipientInfos();
      Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
      RecipientInformation ri = it.next();

      ASN1ObjectIdentifier encAlg = ri.getKeyEncryptionAlgorithm().getAlgorithm();
      Recipient recipient;
      if (encAlg.equals(CMSAlgorithm.ECDH_SHA1KDF)
          || encAlg.equals(CMSAlgorithm.ECDH_SHA224KDF)
          || encAlg.equals(CMSAlgorithm.ECDH_SHA256KDF)
          || encAlg.equals(CMSAlgorithm.ECDH_SHA384KDF)
          || encAlg.equals(CMSAlgorithm.ECDH_SHA384KDF)
          || encAlg.equals(CMSAlgorithm.ECDH_SHA512KDF)) {
        recipient = new JceKeyAgreeEnvelopedRecipient(decKey).setProvider("BC");
      } else {
        recipient = new JceKeyTransEnvelopedRecipient(decKey).setProvider("BC");
      }

      return ri.getContent(recipient);
    } catch (CMSException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  }

  private static byte[] decrypt(EncryptedValue ev, PrivateKey decKey)
      throws XiSecurityException {
    AlgorithmIdentifier keyAlg = ev.getKeyAlg();
    ASN1ObjectIdentifier keyOid = keyAlg.getAlgorithm();

    byte[] symmKey;

    try {
      if (decKey instanceof RSAPrivateKey) {
        Cipher keyCipher;
        if (keyOid.equals(PKCSObjectIdentifiers.id_RSAES_OAEP)) {
          // Currently we only support the default RSAESOAEPparams
          if (keyAlg.getParameters() != null) {
            RSAESOAEPparams params = RSAESOAEPparams.getInstance(keyAlg.getParameters());
            ASN1ObjectIdentifier oid = params.getHashAlgorithm().getAlgorithm();
            if (!oid.equals(RSAESOAEPparams.DEFAULT_HASH_ALGORITHM.getAlgorithm())) {
              throw new XiSecurityException(
                  "unsupported RSAESOAEPparams.HashAlgorithm " + oid.getId());
            }

            oid = params.getMaskGenAlgorithm().getAlgorithm();
            if (!oid.equals(RSAESOAEPparams.DEFAULT_MASK_GEN_FUNCTION.getAlgorithm())) {
              throw new XiSecurityException(
                  "unsupported RSAESOAEPparams.MaskGenAlgorithm " + oid.getId());
            }

            oid = params.getPSourceAlgorithm().getAlgorithm();
            if (!params.getPSourceAlgorithm().equals(RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM)) {
              throw new XiSecurityException(
                  "unsupported RSAESOAEPparams.PSourceAlgorithm " + oid.getId());
            }
          }

          keyCipher = Cipher.getInstance("RSA/NONE/OAEPPADDING");
        } else if (keyOid.equals(PKCSObjectIdentifiers.rsaEncryption)) {
          keyCipher = Cipher.getInstance("RSA/NONE/PKCS1PADDING");
        } else {
          throw new XiSecurityException("unsupported keyAlg " + keyOid.getId());
        }
        keyCipher.init(Cipher.DECRYPT_MODE, decKey);

        symmKey = keyCipher.doFinal(ev.getEncSymmKey().getOctets());
      } else if (decKey instanceof ECPrivateKey) {
        ASN1Sequence params = ASN1Sequence.getInstance(keyAlg.getParameters());
        final int n = params.size();
        for (int i = 0; i < n; i++) {
          if (!keyOid.equals(ObjectIdentifiers.Secg.id_ecies_specifiedParameters)) {
            throw new XiSecurityException("unsupported keyAlg " + keyOid.getId());
          }

          ASN1TaggedObject to = (ASN1TaggedObject) params.getObjectAt(i);
          int tag = to.getTagNo();
          if (tag == 0) { // KDF
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (ObjectIdentifiers.Misc.id_iso18033_kdf2.equals(algId.getAlgorithm())) {
              AlgorithmIdentifier hashAlgorithm =
                  AlgorithmIdentifier.getInstance(algId.getParameters());
              if (!hashAlgorithm.getAlgorithm().equals(HashAlgo.SHA1.getOid())) {
                throw new XiSecurityException("unsupported KeyDerivationFunction.HashAlgorithm "
                    + hashAlgorithm.getAlgorithm().getId());
              }
            } else {
              throw new XiSecurityException(
                  "unsupported KeyDerivationFunction " + algId.getAlgorithm().getId());
            }
          } else if (tag == 1) { // SymmetricEncryption
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (!ObjectIdentifiers.Secg.id_aes128_cbc_in_ecies.equals(algId.getAlgorithm())) {
              throw new XiSecurityException("unsupported SymmetricEncryption "
                  + algId.getAlgorithm().getId());
            }
          } else if (tag == 2) { // MessageAuthenticationCode
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (ObjectIdentifiers.Secg.id_hmac_full_ecies.equals(algId.getAlgorithm())) {
              AlgorithmIdentifier hashAlgorithm =
                  AlgorithmIdentifier.getInstance(algId.getParameters());
              if (!hashAlgorithm.getAlgorithm().equals(HashAlgo.SHA1.getOid())) {
                throw new XiSecurityException("unsupported MessageAuthenticationCode.HashAlgorithm "
                    + hashAlgorithm.getAlgorithm().getId());
              }
            } else {
              throw new XiSecurityException("unsupported MessageAuthenticationCode "
                  + algId.getAlgorithm().getId());
            }
          }
        }

        int aesKeySize = 128;
        byte[] iv = new byte[16];
        AlgorithmParameterSpec spec = new IESParameterSpec(null, null, aesKeySize, aesKeySize, iv);

        BlockCipher cbcCipher = new CBCBlockCipher(new AESEngine());
        IESCipher keyCipher = new IESCipher(
            new IESEngine(new ECDHBasicAgreement(),
                new KDF2BytesGenerator(DigestFactory.createSHA1()),
                new HMac(DigestFactory.createSHA1()),
                new PaddedBufferedBlockCipher(cbcCipher)), 16);
        // no random is required
        keyCipher.engineInit(Cipher.DECRYPT_MODE, decKey, spec, null);

        byte[] encSymmKey = ev.getEncSymmKey().getOctets();
        /*
         * BouncyCastle expects the input ephemeralPublicKey | symmetricCiphertext | macTag.
         * So we have to convert it from the following ASN.1 structure
         * <pre>
         * ECIES-Ciphertext-Value ::= SEQUENCE {
         *     ephemeralPublicKey ECPoint,
         *     symmetricCiphertext OCTET STRING,
         *     macTag OCTET STRING
         * }
         *
         * ECPoint ::= OCTET STRING
         * </pre>
         */
        ASN1Sequence seq = DERSequence.getInstance(encSymmKey);
        byte[] ephemeralPublicKey = DEROctetString.getInstance(seq.getObjectAt(0)).getOctets();
        byte[] symmetricCiphertext = DEROctetString.getInstance(seq.getObjectAt(1)).getOctets();
        byte[] macTag = DEROctetString.getInstance(seq.getObjectAt(2)).getOctets();

        byte[] bcInput = new byte[ephemeralPublicKey.length + symmetricCiphertext.length
            + macTag.length];
        System.arraycopy(ephemeralPublicKey, 0, bcInput, 0, ephemeralPublicKey.length);
        int offset = ephemeralPublicKey.length;
        System.arraycopy(symmetricCiphertext, 0, bcInput, offset, symmetricCiphertext.length);
        offset += symmetricCiphertext.length;
        System.arraycopy(macTag, 0, bcInput, offset, macTag.length);

        symmKey = keyCipher.engineDoFinal(bcInput, 0, bcInput.length);
      } else {
        throw new XiSecurityException("unsupported decryption key type "
            + decKey.getClass().getName());
      }

      AlgorithmIdentifier symmAlg = ev.getSymmAlg();
      ASN1ObjectIdentifier symmAlgOid = symmAlg.getAlgorithm();
      if (!symmAlgOid.equals(NISTObjectIdentifiers.id_aes128_GCM)) {
        // currently we only support AES128-GCM
        throw new XiSecurityException("unsupported symmAlg " + symmAlgOid.getId());
      }
      GCMParameters params = GCMParameters.getInstance(symmAlg.getParameters());
      Cipher dataCipher = Cipher.getInstance(symmAlgOid.getId());
      AlgorithmParameterSpec algParams =
          new GCMParameterSpec(params.getIcvLen() << 3, params.getNonce());
      dataCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(symmKey, "AES"), algParams);

      byte[] encValue = ev.getEncValue().getOctets();
      return dataCipher.doFinal(encValue);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
             | InvalidAlgorithmParameterException | IllegalBlockSizeException
             | BadPaddingException ex) {
      throw new XiSecurityException("Error while decrypting the EncryptedValue", ex);
    }
  } // method decrypt

  private static ASN1Encodable parseGenRep(
      VerifiedPkiMessage response, ASN1ObjectIdentifier expectedType)
      throws CmpClientException, PkiErrorException {
    checkProtection(notNull(response, "response"));
    return parseGenRep(response.getPkiMessage(), expectedType);
  }

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
    if (itvs != null && itvs.length > 0) {
      for (InfoTypeAndValue m : itvs) {
        if (expectedType.equals(m.getInfoType())) {
          itv = m;
          break;
        }
      }
    }

    if (itv == null) {
      throw new CmpClientException("the response does not contain InfoTypeAndValue "
          + expectedType);
    }

    return itv.getInfoValue();
  } // method evaluateCrlResponse

  private static RevokeCertResponse parse(
      VerifiedPkiMessage response, List<? extends UnrevokeCertRequest.Entry> reqEntries)
      throws CmpClientException, PkiErrorException {
    checkProtection(notNull(response, "response"));

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (PKIBody.TYPE_REVOCATION_REP != bodyType) {
      throw new CmpClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]", bodyType,
          PKIBody.TYPE_REVOCATION_REP, PKIBody.TYPE_ERROR));
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
      UnrevokeCertRequest.Entry re = reqEntries.get(i);

      if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
        PKIFreeText text = statusInfo.getStatusString();
        String statusString = (text == null) ? null : text.getStringAt(0).getString();

        ResultEntry resultEntry = new ResultEntry.Error(re.getId(), status,
            statusInfo.getFailInfo().intValue(), statusString);
        result.addResultEntry(resultEntry);
        continue;
      }

      CertId certId = null;
      if (revCerts != null) {
        for (CertId entry : revCerts) {
          if (re.getIssuer().equals(entry.getIssuer().getName())
              && re.getSerialNumber().equals(entry.getSerialNumber().getValue())) {
            certId = entry;
            break;
          }
        }
      }

      if (certId == null) {
        LOG.warn("certId is not present in response for (issuer='{}', serialNumber={})",
            X509Util.getRfc4519Name(re.getIssuer()), LogUtil.formatCsn(re.getSerialNumber()));
        certId = new CertId(new GeneralName(re.getIssuer()), re.getSerialNumber());
      }

      result.addResultEntry(new ResultEntry.RevokeCert(re.getId(), certId));
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
    Extension extAki = new Extension(Extension.authorityKeyIdentifier, false, encodedAki);
    return new Extensions(extAki);
  } // method getCertTempExtensions

}
