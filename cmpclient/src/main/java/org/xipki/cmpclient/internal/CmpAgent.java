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
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.*;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.cmpclient.*;
import org.xipki.security.*;
import org.xipki.security.cmp.*;
import org.xipki.util.DateUtil;
import org.xipki.util.*;
import org.xipki.util.ReqRespDebug.ReqRespPair;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.*;

import static org.xipki.cmpclient.internal.CmpAgentUtil.*;
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

  private final Requestor requestor;

  private final Responder responder;

  private final X500Name recipientName;

  private boolean sendRequestorCert;

  private final boolean implicitConfirm = true;

  private final URL serverUrl;

  private final SSLSocketFactory sslSocketFactory;

  private final HostnameVerifier hostnameVerifier;

  CmpAgent(Requestor requestor, Responder responder,
      String serverUrl, SecurityFactory securityFactory,
      SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier) {

    this.requestor = notNull(requestor, "requestor");
    this.responder = notNull(responder, "responder");
    this.securityFactory = notNull(securityFactory, "securityFactory");
    notBlank(serverUrl, "serverUrl");

    boolean bothSignatureBased = (requestor instanceof Requestor.SignatureCmpRequestor)
        && (responder instanceof Responder.SignatureCmpResponder);
    boolean bothMacBased = (requestor instanceof Requestor.PbmMacCmpRequestor
        && responder instanceof Responder.PbmMacCmpResponder);
    if (!(bothSignatureBased || bothMacBased)) {
      throw new IllegalArgumentException("requestor and responder do not match");
    }

    this.recipientName = (X500Name) responder.getName().getName();

    this.sslSocketFactory = sslSocketFactory;
    this.hostnameVerifier = hostnameVerifier;
    try {
      this.serverUrl = new URL(serverUrl);
    } catch (MalformedURLException ex) {
      throw new IllegalArgumentException("invalid URL: " + serverUrl);
    }
  } // constructor

  private byte[] send(byte[] request)
      throws IOException {
    notNull(request, "request");
    HttpURLConnection httpUrlConnection = IoUtil.openHttpConn(serverUrl);
    if (httpUrlConnection instanceof HttpsURLConnection) {
      if (sslSocketFactory != null) {
        ((HttpsURLConnection) httpUrlConnection).setSSLSocketFactory(sslSocketFactory);
      }

      if (hostnameVerifier != null) {
        ((HttpsURLConnection) httpUrlConnection).setHostnameVerifier(hostnameVerifier);
      }
    }

    httpUrlConnection.setDoOutput(true);
    httpUrlConnection.setUseCaches(false);

    int size = request.length;

    httpUrlConnection.setRequestMethod("POST");
    httpUrlConnection.setRequestProperty("Content-Type", CMP_REQUEST_MIMETYPE);
    httpUrlConnection.setRequestProperty("Content-Length", Integer.toString(size));
    OutputStream outputstream;

    // try max. 3 times
    for (int i = 0; ;i++) {
      try {
        outputstream = httpUrlConnection.getOutputStream();
        break;
      } catch (EOFException ex) {
        if (i == 2) {
          throw ex;
        } else {
          // wait for 200 ms
          try {
            Thread.sleep(200);
          } catch (InterruptedException ex2) {
            // do nothing
          }
        }
      }
    }

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
      if (responseContentType.equalsIgnoreCase(CMP_RESPONSE_MIMETYPE)) {
        isValidContentType = true;
      }
    }

    if (!isValidContentType) {
      inputStream.close();
      throw new IOException("bad response: mime type " + responseContentType + " not supported!");
    }

    return IoUtil.read(inputStream);
  } // method send

  private PKIMessage sign(PKIMessage request)
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

  private VerifiedPkiMessage signAndSend(PKIMessage request, ReqRespDebug debug)
      throws CmpClientException {
    notNull(request, "request");
    PKIMessage tmpRequest = requestor.signRequest() ? sign(request) : request;

    byte[] encodedRequest;
    try {
      encodedRequest = tmpRequest.getEncoded();
    } catch (IOException ex) {
      LOG.error("could not encode the PKI request {}", tmpRequest);
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

    byte[] encodedResponse;
    try {
      encodedResponse = send(encodedRequest);
    } catch (IOException ex) {
      LOG.error("could not send the PKI request {} to server", tmpRequest);
      throw new CmpClientException("TRANSPORT_ERROR", ex);
    }

    if (reqResp != null && debug.saveResponse()) {
      reqResp.setResponse(encodedResponse);
    }

    GeneralPKIMessage response;
    try {
      response = new GeneralPKIMessage(encodedResponse);
    } catch (IOException ex) {
      LOG.error("could not decode the received PKI message: {}", Hex.encode(encodedResponse));
      throw new CmpClientException(ex.getMessage(), ex);
    }

    PKIHeader reqHeader = request.getHeader();
    PKIHeader respHeader = response.getHeader();

    ASN1OctetString tid = reqHeader.getTransactionID();
    ASN1OctetString respTid = respHeader.getTransactionID();
    if (!tid.equals(respTid)) {
      LOG.warn("Response contains different tid ({}) than requested {}", respTid, tid);
      throw new CmpClientException("Response contains differnt tid than the request");
    }

    ASN1OctetString senderNonce = reqHeader.getSenderNonce();
    ASN1OctetString respRecipientNonce = respHeader.getRecipNonce();
    if (!senderNonce.equals(respRecipientNonce)) {
      LOG.warn("tid {}: response.recipientNonce ({}) != request.senderNonce ({})",
          tid, respRecipientNonce, senderNonce);
      throw new CmpClientException("Response contains differnt tid than the request");
    }

    GeneralName rec = respHeader.getRecipient();
    if (!requestor.getName().equals(rec)) {
      LOG.warn("tid={}: unknown CMP requestor '{}'", tid, rec);
    }

    VerifiedPkiMessage ret = new VerifiedPkiMessage(response);
    if (response.hasProtection()) {
      try {
        ProtectionVerificationResult verifyProtection = verifyProtection(
            Hex.encode(tid.getOctets()), response);
        ret.setProtectionVerificationResult(verifyProtection);
      } catch (InvalidKeyException | CMPException ex) {
        throw new CmpClientException(ex.getMessage(), ex);
      }
    } else if (requestor.signRequest()) {
      PKIBody respBody = response.getBody();
      int bodyType = respBody.getType();
      if (bodyType != PKIBody.TYPE_ERROR) {
        throw new CmpClientException("response is not signed");
      }
    }

    return ret;
  } // method signAndSend

  private PKIHeader buildPkiHeader(ASN1OctetString tid) {
    return buildPkiHeader(false, tid, null, (InfoTypeAndValue[]) null);
  }

  private PKIHeader buildPkiHeader(boolean addImplictConfirm, ASN1OctetString tid,
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

    PKIHeaderBuilder hdrBuilder =
        new PKIHeaderBuilder(PKIHeader.CMP_2000, requestor.getName(), responder.getName());
    hdrBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));

    ASN1OctetString tmpTid = (tid == null) ? new DEROctetString(randomTransactionId()) : tid;
    hdrBuilder.setTransactionID(tmpTid);

    hdrBuilder.setSenderNonce(randomSenderNonce());

    List<InfoTypeAndValue> itvs = new ArrayList<>(2);
    if (addImplictConfirm) {
      itvs.add(CmpUtil.getImplictConfirmGeneralInfo());
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

  private ProtectionVerificationResult verifyProtection(String tid, GeneralPKIMessage pkiMessage)
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

      if (recipientName != null) {
        boolean authorizedResponder;
        if (header.getSender().getTagNo() != GeneralName.directoryName) {
          authorizedResponder = false;
        } else {
          X500Name msgSender = X500Name.getInstance(header.getSender().getName());
          authorizedResponder = recipientName.equals(msgSender);
        }

        if (!authorizedResponder) {
          LOG.warn("tid={}: not authorized responder '{}'", tid, header.getSender());
          return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
        }
      }

      Responder.SignatureCmpResponder sigResponder = (Responder.SignatureCmpResponder) responder;
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

  private PKIMessage buildMessageWithXipkiAction(int action, ASN1Encodable value) {
    PKIHeader header = buildPkiHeader(null);

    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(new ASN1Integer(action));
    if (value != null) {
      vec.add(value);
    }

    InfoTypeAndValue itv = new InfoTypeAndValue(ObjectIdentifiers.Xipki.id_xipki_cmp_cmpGenmsg,
        new DERSequence(vec));
    GenMsgContent genMsgContent = new GenMsgContent(itv);
    PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);
    return new PKIMessage(header, body);
  } // method buildMessageWithXipkiAction

  private PKIMessage buildMessageWithGeneralMsgContent(ASN1ObjectIdentifier type,
      ASN1Encodable value) {
    notNull(type, "type");

    PKIHeader header = buildPkiHeader(null);
    InfoTypeAndValue itv = (value != null) ? new InfoTypeAndValue(type, value)
        : new InfoTypeAndValue(type);
    GenMsgContent genMsgContent = new GenMsgContent(itv);
    PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);
    return new PKIMessage(header, body);
  } // method buildMessageWithGeneralMsgContent

  boolean isSendRequestorCert() {
    return sendRequestorCert;
  }

  void setSendRequestorCert(boolean sendRequestorCert) {
    this.sendRequestorCert = sendRequestorCert;
  }

  X509CRLHolder generateCrl(ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    int action = XiSecurityConstants.CMP_ACTION_GEN_CRL;
    PKIMessage request = buildMessageWithXipkiAction(action, null);
    VerifiedPkiMessage response = signAndSend(request, debug);
    return evaluateCrlResponse(response, action);
  } // method generateCrl

  X509CRLHolder downloadCurrentCrl(ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    return downloadCrl(null, debug);
  } // method downloadCurrentCrl

  X509CRLHolder downloadCrl(BigInteger crlNumber, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    Integer action = null;
    PKIMessage request;
    if (crlNumber == null) {
      ASN1ObjectIdentifier type = CMPObjectIdentifiers.it_currentCRL;
      request = buildMessageWithGeneralMsgContent(type, null);
    } else {
      action = XiSecurityConstants.CMP_ACTION_GET_CRL_WITH_SN;
      request = buildMessageWithXipkiAction(action, new ASN1Integer(crlNumber));
    }

    VerifiedPkiMessage response = signAndSend(request, debug);
    return evaluateCrlResponse(response, action);
  } // method downloadCrl

  RevokeCertResponse revokeCertificate(RevokeCertRequest request,
      ReqRespDebug debug)
          throws CmpClientException, PkiErrorException {
    PKIMessage reqMessage = buildRevokeCertRequest(notNull(request, "request"));
    VerifiedPkiMessage response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  } // method revokeCertificate

  RevokeCertResponse unrevokeCertificate(UnrevokeOrRemoveCertRequest request,
      ReqRespDebug debug)
          throws CmpClientException, PkiErrorException {
    PKIMessage reqMessage = buildUnrevokeOrRemoveCertRequest(notNull(request, "request"),
        CrlReason.REMOVE_FROM_CRL.getCode());
    VerifiedPkiMessage response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  } // method unrevokeCertificate

  RevokeCertResponse removeCertificate(UnrevokeOrRemoveCertRequest request,
      ReqRespDebug debug)
          throws CmpClientException, PkiErrorException {
    PKIMessage reqMessage = buildUnrevokeOrRemoveCertRequest(notNull(request, "request"),
            XiSecurityConstants.CMP_CRL_REASON_REMOVE);
    VerifiedPkiMessage response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  } // method removeCertificate

  EnrollCertResponse requestCertificate(CsrEnrollCertRequest csr, Date notBefore,
      Date notAfter, ReqRespDebug debug)
          throws CmpClientException, PkiErrorException {
    PKIMessage request = buildPkiMessage(notNull(csr, "csr"), notBefore, notAfter);
    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    reqIdIdMap.put(MINUS_ONE, csr.getId());
    return requestCertificate0(request, reqIdIdMap, PKIBody.TYPE_CERT_REP, debug);
  } // method requestCertificate

  EnrollCertResponse requestCertificate(EnrollCertRequest req, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    PKIMessage request = buildPkiMessage(notNull(req, "req"));
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

    return requestCertificate0(request, reqIdIdMap, exptectedBodyType, debug);
  } // method requestCertificate

  private EnrollCertResponse requestCertificate0(PKIMessage reqMessage,
      Map<BigInteger, String> reqIdIdMap, int expectedBodyType, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    VerifiedPkiMessage response = signAndSend(reqMessage, debug);
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
    if (!CmpUtil.isImplictConfirm(response.getPkiMessage().getHeader())) {
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
      for (BigInteger reqId : reqIdIdMap.keySet()) {
        ResultEntry.Error ere = new ResultEntry.Error(reqIdIdMap.get(reqId), PKISTATUS_NO_ANSWER);
        result.addResultEntry(ere);
      }
    }

    if (!requireConfirm) {
      return result;
    }

    PKIMessage confirmRequest = buildCertConfirmRequest(
        response.getPkiMessage().getHeader().getTransactionID(), certConfirmBuilder);

    response = signAndSend(confirmRequest, debug);
    checkProtection(response);

    return result;
  } // method requestCertificate0

  private PKIMessage buildCertConfirmRequest(ASN1OctetString tid,
      CertificateConfirmationContentBuilder certConfirmBuilder)
          throws CmpClientException {
    PKIHeader header = buildPkiHeader(implicitConfirm, tid, null, (InfoTypeAndValue[]) null);
    CertificateConfirmationContent certConfirm;
    try {
      certConfirm = certConfirmBuilder.build(DIGEST_CALCULATOR_PROVIDER);
    } catch (CMPException ex) {
      throw new CmpClientException(ex.getMessage(), ex);
    }
    PKIBody body = new PKIBody(PKIBody.TYPE_CERT_CONFIRM, certConfirm.toASN1Structure());
    return new PKIMessage(header, body);
  } // method buildCertConfirmRequest

  private PKIMessage buildRevokeCertRequest(RevokeCertRequest request)
      throws CmpClientException {
    PKIHeader header = buildPkiHeader(null);

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

  private PKIMessage buildUnrevokeOrRemoveCertRequest(UnrevokeOrRemoveCertRequest request,
      int reasonCode)
          throws CmpClientException {
    PKIHeader header = buildPkiHeader(null);

    List<UnrevokeOrRemoveCertRequest.Entry> requestEntries = request.getRequestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (UnrevokeOrRemoveCertRequest.Entry requestEntry : requestEntries) {
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

  private PKIMessage buildPkiMessage(CsrEnrollCertRequest csr, Date notBefore, Date notAfter) {
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

    PKIHeader header = buildPkiHeader(implicitConfirm, null, utf8Pairs, certProfileItv);
    PKIBody body = new PKIBody(PKIBody.TYPE_P10_CERT_REQ, csr.getCsr());

    return new PKIMessage(header, body);
  } // method buildPkiMessage

  private PKIMessage buildPkiMessage(EnrollCertRequest req) {
    List<EnrollCertRequest.Entry> reqEntries = req.getRequestEntries();
    CertReqMsg[] certReqMsgs = new CertReqMsg[reqEntries.size()];

    ASN1EncodableVector vec = new ASN1EncodableVector();

    for (int i = 0; i < reqEntries.size(); i++) {
      EnrollCertRequest.Entry reqEntry = reqEntries.get(i);

      if (reqEntry.getCertprofile() != null) {
        vec.add(new DERUTF8String(reqEntry.getCertprofile()));
      }

      certReqMsgs[i] = new CertReqMsg(reqEntry.getCertReq(), reqEntry.getPopo(), null);
    }

    if (vec.size() != 0 && vec.size() != reqEntries.size()) {
      throw new IllegalStateException("either not all reqEntries have CertProfile or all not" );
    }

    InfoTypeAndValue certProfile = new InfoTypeAndValue(
                    ObjectIdentifiers.CMP.id_it_certProfile, new DERSequence(vec));
    PKIHeader header = buildPkiHeader(implicitConfirm, null, null, certProfile);

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

  CaConf.CaInfo retrieveCaInfo(String caName, ReqRespDebug debug)
      throws CmpClientException, PkiErrorException {
    notBlank(caName, "caName");

    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(new ASN1Integer(3));
    ASN1Sequence acceptVersions = new DERSequence(vec);

    int action = XiSecurityConstants.CMP_ACTION_GET_CAINFO;
    PKIMessage request = buildMessageWithXipkiAction(action, acceptVersions);
    VerifiedPkiMessage response = signAndSend(request, debug);
    return CmpAgentUtil.retrieveCaInfo(response, caName);
  } // method retrieveCaInfo

}
