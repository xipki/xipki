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

package org.xipki.ca.client.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.CertificateConfirmationContent;
import org.bouncycastle.cert.cmp.CertificateConfirmationContentBuilder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
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
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xipki.ca.client.api.CaClientException;
import org.xipki.ca.client.api.CertprofileInfo;
import org.xipki.ca.client.api.PkiErrorException;
import org.xipki.ca.client.api.dto.CsrEnrollCertRequest;
import org.xipki.ca.client.api.dto.EnrollCertRequest;
import org.xipki.ca.client.api.dto.EnrollCertRequestEntry;
import org.xipki.ca.client.api.dto.EnrollCertResultEntry;
import org.xipki.ca.client.api.dto.EnrollCertResultResp;
import org.xipki.ca.client.api.dto.ErrorResultEntry;
import org.xipki.ca.client.api.dto.IssuerSerialEntry;
import org.xipki.ca.client.api.dto.ResultEntry;
import org.xipki.ca.client.api.dto.RevokeCertRequest;
import org.xipki.ca.client.api.dto.RevokeCertRequestEntry;
import org.xipki.ca.client.api.dto.RevokeCertResultEntry;
import org.xipki.ca.client.api.dto.RevokeCertResultType;
import org.xipki.ca.client.api.dto.UnrevokeOrRemoveCertEntry;
import org.xipki.ca.client.api.dto.UnrevokeOrRemoveCertRequest;
import org.xipki.cmp.CmpUtf8Pairs;
import org.xipki.cmp.CmpUtil;
import org.xipki.cmp.PkiResponse;
import org.xipki.cmp.ProtectionResult;
import org.xipki.cmp.ProtectionVerificationResult;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SecurityFactory;
import org.xipki.security.XiSecurityConstants;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.CmpFailureUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.DateUtil;
import org.xipki.util.Hex;
import org.xipki.util.LogUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.ReqRespDebug;
import org.xipki.util.ReqRespDebug.ReqRespPair;
import org.xipki.util.StringUtil;
import org.xipki.util.XmlUtil;
import org.xml.sax.SAXException;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class ClientCmpAgent {

  private static final Logger LOG = LoggerFactory.getLogger(ClientCmpAgent.class);

  private static final DigestCalculatorProvider DIGEST_CALCULATOR_PROVIDER =
      new BcDigestCalculatorProvider();

  private static final DefaultSecretKeySizeProvider KEYSIZE_PROVIDER =
      new DefaultSecretKeySizeProvider();

  private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);

  /**
   * Intern status to indicate that there are errors in the response.
   */
  protected static final int PKISTATUS_RESPONSE_ERROR = -1;

  protected static final int PKISTATUS_NO_ANSWER = -2;

  protected final SecurityFactory securityFactory;

  private final Random random = new Random();

  private final ClientCmpRequestor requestor;

  private final ClientCmpResponder responder;

  private final X500Name recipientName;

  private boolean sendRequestorCert;

  private final DocumentBuilder xmlDocBuilder;

  private boolean implicitConfirm = true;

  public ClientCmpAgent(ClientCmpRequestor requestor, ClientCmpResponder responder,
      SecurityFactory securityFactory) {
    this.requestor = ParamUtil.requireNonNull("requestor", requestor);
    this.responder = ParamUtil.requireNonNull("responder", responder);
    this.securityFactory = ParamUtil.requireNonNull("securityFactory", securityFactory);

    boolean bothSignatureBased = (requestor instanceof SignatureClientCmpRequestor)
        && (responder instanceof SignatureClientCmpResponder);
    boolean bothMacBased = (requestor instanceof PbmMacClientCmpRequestor
        && responder instanceof PbmMacClientCmpResponder);
    if (!(bothSignatureBased || bothMacBased)) {
      throw new IllegalArgumentException("requestor and responder do not match");
    }

    this.recipientName = (X500Name) responder.getName().getName();

    this.xmlDocBuilder = newDocumentBuilder();
  }

  protected abstract byte[] send(byte[] request) throws IOException;

  protected PKIMessage sign(PKIMessage request) throws CaClientException {
    ParamUtil.requireNonNull("request", request);
    if (requestor == null) {
      throw new CaClientException("no request signer is configured");
    }

    if (requestor instanceof SignatureClientCmpRequestor) {
      ConcurrentContentSigner signer = ((SignatureClientCmpRequestor) requestor).getSigner();
      try {
        return CmpUtil.addProtection(request, signer, requestor.getName(), sendRequestorCert);
      } catch (CMPException | NoIdleSignerException ex) {
        throw new CaClientException("could not sign the request", ex);
      }
    } else {
      PbmMacClientCmpRequestor pbmRequestor = (PbmMacClientCmpRequestor) requestor;

      try {
        return CmpUtil.addProtection(request, pbmRequestor.getPassword(),
            pbmRequestor.getParameter(), requestor.getName(), pbmRequestor.getSenderKID());
      } catch (CMPException ex) {
        throw new CaClientException("could not sign the request", ex);
      }
    }
  }

  protected PkiResponse signAndSend(PKIMessage request, ReqRespDebug debug)
      throws CaClientException {
    ParamUtil.requireNonNull("request", request);
    PKIMessage tmpRequest = requestor.signRequest() ? sign(request) : request;

    byte[] encodedRequest;
    try {
      encodedRequest = tmpRequest.getEncoded();
    } catch (IOException ex) {
      LOG.error("could not encode the PKI request {}", tmpRequest);
      throw new CaClientException(ex.getMessage(), ex);
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
      throw new CaClientException("TRANSPORT_ERROR", ex);
    }

    if (reqResp != null && debug.saveResponse()) {
      reqResp.setResponse(encodedResponse);
    }

    GeneralPKIMessage response;
    try {
      response = new GeneralPKIMessage(encodedResponse);
    } catch (IOException ex) {
      LOG.error("could not decode the received PKI message: {}", Hex.encode(encodedResponse));
      throw new CaClientException(ex.getMessage(), ex);
    }

    PKIHeader reqHeader = request.getHeader();
    PKIHeader respHeader = response.getHeader();

    ASN1OctetString tid = reqHeader.getTransactionID();
    ASN1OctetString respTid = respHeader.getTransactionID();
    if (!tid.equals(respTid)) {
      LOG.warn("Response contains different tid ({}) than requested {}", respTid, tid);
      throw new CaClientException("Response contains differnt tid than the request");
    }

    ASN1OctetString senderNonce = reqHeader.getSenderNonce();
    ASN1OctetString respRecipientNonce = respHeader.getRecipNonce();
    if (!senderNonce.equals(respRecipientNonce)) {
      LOG.warn("tid {}: response.recipientNonce ({}) != request.senderNonce ({})",
          tid, respRecipientNonce, senderNonce);
      throw new CaClientException("Response contains differnt tid than the request");
    }

    GeneralName rec = respHeader.getRecipient();
    if (!requestor.getName().equals(rec)) {
      LOG.warn("tid={}: unknown CMP requestor '{}'", tid, rec);
    }

    PkiResponse ret = new PkiResponse(response);
    if (response.hasProtection()) {
      try {
        ProtectionVerificationResult verifyProtection = verifyProtection(
            Hex.encode(tid.getOctets()), response);
        ret.setProtectionVerificationResult(verifyProtection);
      } catch (InvalidKeyException | OperatorCreationException | CMPException ex) {
        throw new CaClientException(ex.getMessage(), ex);
      }
    } else if (requestor.signRequest()) {
      PKIBody respBody = response.getBody();
      int bodyType = respBody.getType();
      if (bodyType != PKIBody.TYPE_ERROR) {
        throw new CaClientException("response is not signed");
      }
    }

    return ret;
  } // method signAndSend

  protected ASN1Encodable extractGeneralRepContent(PkiResponse response, String expectedType)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("response", response);
    ParamUtil.requireNonNull("expectedType", expectedType);
    return extractGeneralRepContent(response, expectedType, true);
  }

  private ASN1Encodable extractGeneralRepContent(PkiResponse response, String expectedType,
      boolean requireProtectionCheck) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("response", response);
    ParamUtil.requireNonNull("expectedType", expectedType);
    if (requireProtectionCheck) {
      checkProtection(response);
    }

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new CaClientException(CmpFailureUtil.formatPkiStatusInfo(
          content.getPKIStatusInfo()));
    } else if (PKIBody.TYPE_GEN_REP != bodyType) {
      throw new CaClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]", bodyType,
          PKIBody.TYPE_GEN_REP, PKIBody.TYPE_ERROR));
    }

    GenRepContent genRep = GenRepContent.getInstance(respBody.getContent());

    InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
    InfoTypeAndValue itv = null;
    if (itvs != null && itvs.length > 0) {
      for (InfoTypeAndValue entry : itvs) {
        if (expectedType.equals(entry.getInfoType().getId())) {
          itv = entry;
          break;
        }
      }
    }

    if (itv == null) {
      throw new CaClientException("the response does not contain InfoTypeAndValue "
          + expectedType);
    }

    return itv.getInfoValue();
  } // method extractGeneralRepContent

  protected ASN1Encodable extractXipkiActionRepContent(PkiResponse response, int action)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("response", response);
    ASN1Encodable itvValue = extractGeneralRepContent(response,
        ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId(), true);
    return extractXiActionContent(itvValue, action);
  }

  protected ASN1Encodable extractXiActionContent(ASN1Encodable itvValue, int action)
      throws CaClientException {
    ParamUtil.requireNonNull("itvValue", itvValue);
    ASN1Sequence seq;
    try {
      seq = ASN1Sequence.getInstance(itvValue);
    } catch (IllegalArgumentException ex) {
      throw new CaClientException("invalid syntax of the response");
    }

    int size = seq.size();
    if (size != 1 && size != 2) {
      throw new CaClientException("invalid syntax of the response");
    }

    int tmpAction;
    try {
      tmpAction = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue().intValue();
    } catch (IllegalArgumentException ex) {
      throw new CaClientException("invalid syntax of the response");
    }

    if (action != tmpAction) {
      throw new CaClientException("received XiPKI action '" + tmpAction
          + "' instead the expected '" + action + "'");
    }

    return (size == 1) ? null : seq.getObjectAt(1);
  } // method extractXipkiActionContent

  protected PKIHeader buildPkiHeader(ASN1OctetString tid) {
    return buildPkiHeader(false, tid, (CmpUtf8Pairs) null, (InfoTypeAndValue[]) null);
  }

  protected PKIHeader buildPkiHeader(boolean addImplictConfirm, ASN1OctetString tid) {
    return buildPkiHeader(addImplictConfirm, tid, (CmpUtf8Pairs) null, (InfoTypeAndValue[]) null);
  }

  protected PKIHeader buildPkiHeader(boolean addImplictConfirm, ASN1OctetString tid,
      CmpUtf8Pairs utf8Pairs, InfoTypeAndValue... additionalGeneralInfos) {
    if (additionalGeneralInfos != null) {
      for (InfoTypeAndValue itv : additionalGeneralInfos) {
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

    if (CollectionUtil.isNonEmpty(itvs)) {
      hdrBuilder.setGeneralInfo(itvs.toArray(new InfoTypeAndValue[0]));
    }

    return hdrBuilder.build();
  } // method buildPkiHeader

  protected PkiErrorException buildErrorResult(ErrorMsgContent bodyContent) {
    ParamUtil.requireNonNull("bodyContent", bodyContent);

    org.xipki.cmp.PkiStatusInfo statusInfo =
        new org.xipki.cmp.PkiStatusInfo(bodyContent.getPKIStatusInfo());
    return new PkiErrorException(statusInfo.status(), statusInfo.pkiFailureInfo(),
        statusInfo.statusMessage());
  }

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
      throws CMPException, InvalidKeyException, OperatorCreationException {
    ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

    PKIHeader header = protectedMsg.getHeader();

    if (requestor instanceof PbmMacClientCmpRequestor) {
      if (!protectedMsg.hasPasswordBasedMacProtection()) {
        LOG.warn("NOT_MAC_BASED: {}",
            pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
        return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      PbmMacClientCmpResponder macResponder = (PbmMacClientCmpResponder) responder;
      PBMParameter parameter =
          PBMParameter.getInstance(pkiMessage.getHeader().getProtectionAlg().getParameters());
      AlgorithmIdentifier algId = parameter.getOwf();
      if (!macResponder.isPbmOwfPermitted(algId)) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.owf: {})", algId.getAlgorithm().getId());
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      algId = parameter.getMac();
      if (!macResponder.isPbmMacPermitted(algId)) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.mac: {})", algId.getAlgorithm().getId());
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      PbmMacClientCmpRequestor macRequestor = (PbmMacClientCmpRequestor) requestor;
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
        boolean authorizedResponder = true;
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

      SignatureClientCmpResponder sigResponder = (SignatureClientCmpResponder) responder;
      AlgorithmIdentifier protectionAlgo = protectedMsg.getHeader().getProtectionAlg();
      if (!sigResponder.getSigAlgoValidator().isAlgorithmPermitted(protectionAlgo)) {
        String algoName;
        try {
          algoName = AlgorithmUtil.getSignatureAlgoName(protectionAlgo);
        } catch (NoSuchAlgorithmException ex) {
          algoName = protectionAlgo.getAlgorithm().getId();
        }
        LOG.warn("tid={}: response protected by untrusted protection algorithm '{}'",
            tid, algoName);
        return new ProtectionVerificationResult(null, ProtectionResult.SIGNATURE_INVALID);
      }

      X509Certificate cert = sigResponder.getCert();
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

  protected PKIMessage buildMessageWithXipkAction(int action, ASN1Encodable value) {
    PKIHeader header = buildPkiHeader(null);

    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(new ASN1Integer(action));
    if (value != null) {
      vec.add(value);
    }

    InfoTypeAndValue itv = new InfoTypeAndValue(ObjectIdentifiers.id_xipki_cmp_cmpGenmsg,
        new DERSequence(vec));
    GenMsgContent genMsgContent = new GenMsgContent(itv);
    PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);
    return new PKIMessage(header, body);
  }

  protected PKIMessage buildMessageWithGeneralMsgContent(ASN1ObjectIdentifier type,
      ASN1Encodable value) {
    ParamUtil.requireNonNull("type", type);

    PKIHeader header = buildPkiHeader(null);
    InfoTypeAndValue itv = (value != null) ? new InfoTypeAndValue(type, value)
        : new InfoTypeAndValue(type);
    GenMsgContent genMsgContent = new GenMsgContent(itv);
    PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);
    return new PKIMessage(header, body);
  }

  protected void checkProtection(PkiResponse response) throws PkiErrorException {
    ParamUtil.requireNonNull("response", response);

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
  }

  public boolean isSendRequestorCert() {
    return sendRequestorCert;
  }

  public void setSendRequestorCert(boolean sendRequestorCert) {
    this.sendRequestorCert = sendRequestorCert;
  }

  private static byte[] decrypt(EncryptedValue ev, char[] password) throws XiSecurityException {
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
          if (!keyOid.equals(ObjectIdentifiers.id_ecies_specifiedParameters)) {
            throw new XiSecurityException("unsupported keyAlg " + keyOid.getId());
          }

          ASN1TaggedObject to = (ASN1TaggedObject) params.getObjectAt(i);
          int tag = to.getTagNo();
          if (tag == 0) { // KDF
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (ObjectIdentifiers.id_iso18033_kdf2.equals(algId.getAlgorithm())) {
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
            if (!ObjectIdentifiers.id_aes128_cbc_in_ecies.equals(algId.getAlgorithm())) {
              throw new XiSecurityException("unsupported SymmetricEncryption "
                  + algId.getAlgorithm().getId());
            }
          } else if (tag == 2) { // MessageAuthenticationCode
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(to.getObject());
            if (ObjectIdentifiers.id_hmac_full_ecies.equals(algId.getAlgorithm())) {
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
        | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
      throw new XiSecurityException("Error while decrypting the EncryptedValue", ex);
    }
  }

  public X509CRL generateCrl(ReqRespDebug debug) throws CaClientException, PkiErrorException {
    int action = XiSecurityConstants.CMP_ACTION_GEN_CRL;
    PKIMessage request = buildMessageWithXipkAction(action, null);
    PkiResponse response = signAndSend(request, debug);
    return evaluateCrlResponse(response, action);
  }

  public X509CRL downloadCurrentCrl(ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    return downloadCrl((BigInteger) null, debug);
  }

  public X509CRL downloadCrl(BigInteger crlNumber, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    Integer action = null;
    PKIMessage request;
    if (crlNumber == null) {
      ASN1ObjectIdentifier type = CMPObjectIdentifiers.it_currentCRL;
      request = buildMessageWithGeneralMsgContent(type, null);
    } else {
      action = XiSecurityConstants.CMP_ACTION_GET_CRL_WITH_SN;
      request = buildMessageWithXipkAction(action, new ASN1Integer(crlNumber));
    }

    PkiResponse response = signAndSend(request, debug);
    return evaluateCrlResponse(response, action);
  }

  private X509CRL evaluateCrlResponse(PkiResponse response, Integer xipkiAction)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("response", response);

    checkProtection(response);

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (PKIBody.TYPE_GEN_REP != bodyType) {
      throw new CaClientException(String.format(
          "unknown PKI body type %s instead the expected [%s, %s]",
          bodyType, PKIBody.TYPE_GEN_REP, PKIBody.TYPE_ERROR));
    }

    ASN1ObjectIdentifier expectedType = (xipkiAction == null)
        ? CMPObjectIdentifiers.it_currentCRL : ObjectIdentifiers.id_xipki_cmp_cmpGenmsg;

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
      throw new CaClientException("the response does not contain InfoTypeAndValue "
          + expectedType);
    }

    ASN1Encodable certListAsn1Object = (xipkiAction == null) ? itv.getInfoValue()
        : extractXiActionContent(itv.getInfoValue(), xipkiAction);

    CertificateList certList = CertificateList.getInstance(certListAsn1Object);

    X509CRL crl;
    try {
      crl = X509Util.toX509Crl(certList);
    } catch (CRLException | CertificateException ex) {
      throw new CaClientException("returned CRL is invalid: " + ex.getMessage());
    }

    return crl;
  } // method evaluateCrlResponse

  public RevokeCertResultType revokeCertificate(RevokeCertRequest request,
      ReqRespDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("request", request);

    PKIMessage reqMessage = buildRevokeCertRequest(request);
    PkiResponse response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  }

  public RevokeCertResultType unrevokeCertificate(UnrevokeOrRemoveCertRequest request,
      ReqRespDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("request", request);

    PKIMessage reqMessage = buildUnrevokeOrRemoveCertRequest(request,
        CrlReason.REMOVE_FROM_CRL.getCode());
    PkiResponse response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  }

  public RevokeCertResultType removeCertificate(UnrevokeOrRemoveCertRequest request,
      ReqRespDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("request", request);

    PKIMessage reqMessage = buildUnrevokeOrRemoveCertRequest(request,
            XiSecurityConstants.CMP_CRL_REASON_REMOVE);
    PkiResponse response = signAndSend(reqMessage, debug);
    return parse(response, request.getRequestEntries());
  }

  private RevokeCertResultType parse(PkiResponse response,
      List<? extends IssuerSerialEntry> reqEntries) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("response", response);

    checkProtection(response);

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (PKIBody.TYPE_REVOCATION_REP != bodyType) {
      throw new CaClientException(String.format(
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

      throw new CaClientException(String.format(
          "incorrect number of status entries in response '%s' instead the expected '%s'",
          statusesLen, reqEntries.size()));
    }

    CertId[] revCerts = content.getRevCerts();

    RevokeCertResultType result = new RevokeCertResultType();
    for (int i = 0; i < statuses.length; i++) {
      PKIStatusInfo statusInfo = statuses[i];
      int status = statusInfo.getStatus().intValue();
      IssuerSerialEntry re = reqEntries.get(i);

      if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS) {
        PKIFreeText text = statusInfo.getStatusString();
        String statusString = (text == null) ? null : text.getStringAt(0).getString();

        ResultEntry resultEntry = new ErrorResultEntry(re.getId(), status,
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
        continue;
      }

      ResultEntry resultEntry = new RevokeCertResultEntry(re.getId(), certId);
      result.addResultEntry(resultEntry);
    }

    return result;
  } // method parse

  public EnrollCertResultResp requestCertificate(CsrEnrollCertRequest csr, Date notBefore,
      Date notAfter, ReqRespDebug debug) throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("csr", csr);

    PKIMessage request = buildPkiMessage(csr, notBefore, notAfter);
    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    reqIdIdMap.put(MINUS_ONE, csr.getId());
    return requestCertificate0(request, reqIdIdMap, PKIBody.TYPE_CERT_REP, debug);
  }

  public EnrollCertResultResp requestCertificate(EnrollCertRequest req, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonNull("req", req);

    PKIMessage request = buildPkiMessage(req);
    Map<BigInteger, String> reqIdIdMap = new HashMap<>();
    List<EnrollCertRequestEntry> reqEntries = req.getRequestEntries();

    for (EnrollCertRequestEntry reqEntry : reqEntries) {
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
  }

  private EnrollCertResultResp requestCertificate0(PKIMessage reqMessage,
      Map<BigInteger, String> reqIdIdMap, int expectedBodyType, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    PkiResponse response = signAndSend(reqMessage, debug);
    checkProtection(response);

    PKIBody respBody = response.getPkiMessage().getBody();
    final int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new PkiErrorException(content.getPKIStatusInfo());
    } else if (expectedBodyType != bodyType) {
      throw new CaClientException(String.format(
              "unknown PKI body type %s instead the expected [%s, %s]", bodyType,
              expectedBodyType, PKIBody.TYPE_ERROR));
    }

    CertRepMessage certRep = CertRepMessage.getInstance(respBody.getContent());
    CertResponse[] certResponses = certRep.getResponse();

    EnrollCertResultResp result = new EnrollCertResultResp();

    // CA certificates
    CMPCertificate[] caPubs = certRep.getCaPubs();
    if (caPubs != null && caPubs.length > 0) {
      for (int i = 0; i < caPubs.length; i++) {
        if (caPubs[i] != null) {
          result.addCaCertificate(caPubs[i]);
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
          resultEntry = new ErrorResultEntry(thisId, PKISTATUS_RESPONSE_ERROR,
              PKIFailureInfo.systemFailure, "could not decrypt PrivateKeyInfo/requestor is null");
          continue;
        }

        PrivateKeyInfo privKeyInfo = null;
        if (cvk.getPrivateKey() != null) {
          // decryp the encrypted private key
          byte[] decryptedValue;
          try {
            if (requestor instanceof SignatureClientCmpRequestor) {
              ConcurrentContentSigner requestSigner =
                  ((SignatureClientCmpRequestor) requestor).getSigner();
              if (!(requestSigner.getSigningKey() instanceof PrivateKey)) {
                throw new XiSecurityException("no decryption key is configured");
              }

              decryptedValue = decrypt(cvk.getPrivateKey(),
                  (PrivateKey) requestSigner.getSigningKey());
            } else {
              decryptedValue = decrypt(cvk.getPrivateKey(),
                  ((PbmMacClientCmpRequestor) requestor).getPassword());
            }
          } catch (XiSecurityException ex) {
            resultEntry = new ErrorResultEntry(thisId, PKISTATUS_RESPONSE_ERROR,
                PKIFailureInfo.systemFailure, "could not decrypt PrivateKeyInfo");
            continue;
          }
          privKeyInfo = PrivateKeyInfo.getInstance(decryptedValue);
        }

        resultEntry = new EnrollCertResultEntry(thisId, cmpCert, privKeyInfo, status);

        if (certConfirmBuilder != null) {
          requireConfirm = true;
          X509CertificateHolder certHolder = null;
          try {
            certHolder = new X509CertificateHolder(cmpCert.getEncoded());
          } catch (IOException ex) {
            resultEntry = new ErrorResultEntry(thisId, PKISTATUS_RESPONSE_ERROR,
                PKIFailureInfo.systemFailure, "could not decode the certificate");
          }

          if (certHolder != null) {
            certConfirmBuilder.addAcceptedCertificate(certHolder, certReqId);
          }
        }
      } else {
        PKIFreeText statusString = statusInfo.getStatusString();
        String errorMessage = (statusString == null)
            ? null : statusString.getStringAt(0).getString();
        int failureInfo = statusInfo.getFailInfo().intValue();

        resultEntry = new ErrorResultEntry(thisId, status, failureInfo, errorMessage);
      }
      result.addResultEntry(resultEntry);
    }

    if (CollectionUtil.isNonEmpty(reqIdIdMap)) {
      for (BigInteger reqId : reqIdIdMap.keySet()) {
        ErrorResultEntry ere = new ErrorResultEntry(reqIdIdMap.get(reqId), PKISTATUS_NO_ANSWER);
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
      CertificateConfirmationContentBuilder certConfirmBuilder) throws CaClientException {
    PKIHeader header = buildPkiHeader(implicitConfirm, tid, null, (InfoTypeAndValue[]) null);
    CertificateConfirmationContent certConfirm;
    try {
      certConfirm = certConfirmBuilder.build(DIGEST_CALCULATOR_PROVIDER);
    } catch (CMPException ex) {
      throw new CaClientException(ex.getMessage(), ex);
    }
    PKIBody body = new PKIBody(PKIBody.TYPE_CERT_CONFIRM, certConfirm.toASN1Structure());
    return new PKIMessage(header, body);
  }

  private PKIMessage buildRevokeCertRequest(RevokeCertRequest request)
      throws CaClientException {
    PKIHeader header = buildPkiHeader(null);

    List<RevokeCertRequestEntry> requestEntries = request.getRequestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (RevokeCertRequestEntry requestEntry : requestEntries) {
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
        throw new CaClientException(ex.getMessage(), ex);
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
      int reasonCode) throws CaClientException {
    PKIHeader header = buildPkiHeader(null);

    List<UnrevokeOrRemoveCertEntry> requestEntries = request.getRequestEntries();
    List<RevDetails> revDetailsArray = new ArrayList<>(requestEntries.size());
    for (UnrevokeOrRemoveCertEntry requestEntry : requestEntries) {
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
        throw new CaClientException(ex.getMessage(), ex);
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
    CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(CmpUtf8Pairs.KEY_CERTPROFILE, csr.getCertprofile());

    if (notBefore != null) {
      utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_NOTBEFORE,
          DateUtil.toUtcTimeyyyyMMddhhmmss(notBefore));
    }

    if (notAfter != null) {
      utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_NOTAFTER, DateUtil.toUtcTimeyyyyMMddhhmmss(notAfter));
    }

    PKIHeader header = buildPkiHeader(implicitConfirm, null, utf8Pairs);
    PKIBody body = new PKIBody(PKIBody.TYPE_P10_CERT_REQ, csr.getCsr());

    return new PKIMessage(header, body);
  }

  private PKIMessage buildPkiMessage(EnrollCertRequest req) {
    PKIHeader header = buildPkiHeader(implicitConfirm, null);

    List<EnrollCertRequestEntry> reqEntries = req.getRequestEntries();
    CertReqMsg[] certReqMsgs = new CertReqMsg[reqEntries.size()];

    for (int i = 0; i < reqEntries.size(); i++) {
      EnrollCertRequestEntry reqEntry = reqEntries.get(i);

      AttributeTypeAndValue[] reginfo = null;

      CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs();
      if (reqEntry.getCertprofile() != null) {
        utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_CERTPROFILE, reqEntry.getCertprofile());
      }

      if (reqEntry.isCaGenerateKeypair()) {
        utf8Pairs.putUtf8Pair(CmpUtf8Pairs.KEY_CA_GENERATE_KEYPAIR, "true");
      }

      if (!utf8Pairs.names().isEmpty()) {
        AttributeTypeAndValue atv = CmpUtil.buildAttributeTypeAndValue(utf8Pairs);
        reginfo = new AttributeTypeAndValue[]{atv};
      }
      certReqMsgs[i] = new CertReqMsg(reqEntry.getCertReq(), reqEntry.getPopo(), reginfo);
    }

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

  public ClientCaInfo retrieveCaInfo(String caName, ReqRespDebug debug)
      throws CaClientException, PkiErrorException {
    ParamUtil.requireNonBlank("caName", caName);

    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(new ASN1Integer(2));
    ASN1Sequence acceptVersions = new DERSequence(vec);

    int action = XiSecurityConstants.CMP_ACTION_GET_CAINFO;
    PKIMessage request = buildMessageWithXipkAction(action, acceptVersions);
    PkiResponse response = signAndSend(request, debug);
    ASN1Encodable itvValue = extractXipkiActionRepContent(response, action);
    DERUTF8String utf8Str = DERUTF8String.getInstance(itvValue);
    String systemInfoStr = utf8Str.getString();

    LOG.debug("CAInfo for CA {}: {}", caName, systemInfoStr);
    Document doc;
    try {
      doc = xmlDocBuilder.parse(new ByteArrayInputStream(systemInfoStr.getBytes("UTF-8")));
    } catch (SAXException | IOException ex) {
      throw new CaClientException("could not parse the returned systemInfo for CA "
          + caName + ": " + ex.getMessage(), ex);
    }

    final String namespace = null;
    Element root = doc.getDocumentElement();
    String str = root.getAttribute("version");
    if (StringUtil.isBlank(str)) {
      str = root.getAttributeNS(namespace, "version");
    }

    int version = StringUtil.isBlank(str) ? 1 : Integer.parseInt(str);

    if (version == 2) {
      // CACert
      X509Certificate caCert;
      String b64CaCert = XmlUtil.getValueOfFirstElementChild(root, namespace, "CACert");
      try {
        caCert = X509Util.parseCert(b64CaCert.getBytes());
      } catch (CertificateException ex) {
        throw new CaClientException("could no parse the CA certificate", ex);
      }

      // CmpControl
      ClientCmpControl cmpControl = null;
      Element cmpCtrlElement = XmlUtil.getFirstElementChild(root, namespace, "cmpControl");
      if (cmpCtrlElement != null) {
        String tmpStr = XmlUtil.getValueOfFirstElementChild(cmpCtrlElement, namespace,
            "rrAkiRequired");
        boolean required = (tmpStr == null) ? false : Boolean.parseBoolean(tmpStr);
        cmpControl = new ClientCmpControl(required);
      }

      // certprofiles
      Set<String> profileNames = new HashSet<>();
      Element profilesElement = XmlUtil.getFirstElementChild(root, namespace, "certprofiles");
      Set<CertprofileInfo> profiles = new HashSet<>();
      if (profilesElement != null) {
        List<Element> profileElements = XmlUtil.getElementChilden(profilesElement, namespace,
            "certprofile");

        for (Element element : profileElements) {
          String name = XmlUtil.getValueOfFirstElementChild(element, namespace, "name");
          String type = XmlUtil.getValueOfFirstElementChild(element, namespace, "type");
          String conf = XmlUtil.getValueOfFirstElementChild(element, namespace, "conf");
          CertprofileInfo profile = new CertprofileInfo(name, type, conf);
          profiles.add(profile);
          profileNames.add(name);
          LOG.debug("configured for CA {} certprofile (name={}, type={}, conf={})", caName, name,
              type, conf);
        }
      }

      LOG.info("CA {} supports profiles {}", caName, profileNames);
      return new ClientCaInfo(caCert, cmpControl, profiles);
    } else {
      throw new CaClientException("unknown CAInfo version " + version);
    }
  } // method retrieveCaInfo

  private static DocumentBuilder newDocumentBuilder() {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    try {
      return dbf.newDocumentBuilder();
    } catch (ParserConfigurationException ex) {
      throw new IllegalStateException("could not create XML document builder", ex);
    }
  }

  private static Extensions getCertTempExtensions(byte[] authorityKeyIdentifier)
      throws CaClientException {
    AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(authorityKeyIdentifier);
    byte[] encodedAki;
    try {
      encodedAki = aki.getEncoded();
    } catch (IOException ex) {
      throw new CaClientException("could not encoded AuthorityKeyIdentifier", ex);
    }
    Extension extAki = new Extension(Extension.authorityKeyIdentifier, false, encodedAki);
    Extensions certTempExts = new Extensions(extAki);
    return certTempExts;
  }

}
