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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cms.CMSAlgorithm;
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
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.client.api.PkiErrorException;
import org.xipki.cmp.CmpUtf8Pairs;
import org.xipki.cmp.CmpUtil;
import org.xipki.cmp.PkiResponse;
import org.xipki.cmp.ProtectionResult;
import org.xipki.cmp.ProtectionVerificationResult;
import org.xipki.common.RequestResponseDebug;
import org.xipki.common.RequestResponseDebug.RequestResponsePair;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.Hex;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SecurityFactory;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.CmpFailureUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class CmpRequestor {

  private static final Logger LOG = LoggerFactory.getLogger(CmpRequestor.class);

  protected final SecurityFactory securityFactory;

  private final Random random = new Random();

  private final ConcurrentContentSigner requestor;

  private final GeneralName sender;

  private final CmpResponder responder;

  private final GeneralName recipient;

  private final X500Name recipientName;

  private boolean signRequest;

  private boolean sendRequestorCert;

  public CmpRequestor(X509Certificate requestorCert, CmpResponder responder,
      SecurityFactory securityFactory) {
    ParamUtil.requireNonNull("requestorCert", requestorCert);
    this.responder = ParamUtil.requireNonNull("responder", responder);
    this.securityFactory = ParamUtil.requireNonNull("securityFactory", securityFactory);
    this.requestor = null;

    X500Name x500Name = X500Name.getInstance(requestorCert.getSubjectX500Principal().getEncoded());
    this.sender = new GeneralName(x500Name);

    X500Name subject = X500Name.getInstance(responder.getCert().getSubjectX500Principal()
        .getEncoded());
    this.recipient = new GeneralName(subject);
    this.recipientName = subject;
  }

  public CmpRequestor(ConcurrentContentSigner requestor, CmpResponder responder,
      SecurityFactory securityFactory) {
    this.requestor = ParamUtil.requireNonNull("requestor", requestor);
    if (requestor.getCertificate() == null) {
      throw new IllegalArgumentException("requestor without certificate is not allowed");
    }
    this.responder = ParamUtil.requireNonNull("responder", responder);
    this.securityFactory = ParamUtil.requireNonNull("securityFactory", securityFactory);

    X500Name x500Name = X500Name.getInstance(requestor.getCertificate().getSubjectX500Principal()
        .getEncoded());
    this.sender = new GeneralName(x500Name);

    X500Name subject = X500Name.getInstance(responder.getCert().getSubjectX500Principal()
        .getEncoded());
    this.recipient = new GeneralName(subject);
    this.recipientName = subject;
  }

  protected abstract byte[] send(byte[] request) throws IOException;

  protected PKIMessage sign(PKIMessage request) throws CmpRequestorException {
    ParamUtil.requireNonNull("request", request);
    if (requestor == null) {
      throw new CmpRequestorException("no request signer is configured");
    }

    try {
      return CmpUtil.addProtection(request, requestor, sender, sendRequestorCert);
    } catch (CMPException | NoIdleSignerException ex) {
      throw new CmpRequestorException("could not sign the request", ex);
    }
  }

  protected PkiResponse signAndSend(PKIMessage request, RequestResponseDebug debug)
      throws CmpRequestorException {
    ParamUtil.requireNonNull("request", request);

    PKIMessage tmpRequest = (signRequest) ? sign(request) : request;

    byte[] encodedRequest;
    try {
      encodedRequest = tmpRequest.getEncoded();
    } catch (IOException ex) {
      LOG.error("could not encode the PKI request {}", tmpRequest);
      throw new CmpRequestorException(ex.getMessage(), ex);
    }

    RequestResponsePair reqResp = null;
    if (debug != null) {
      reqResp = new RequestResponsePair();
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
      throw new CmpRequestorException("TRANSPORT_ERROR", ex);
    }

    if (reqResp != null && debug.saveResponse()) {
      reqResp.setResponse(encodedResponse);
    }

    GeneralPKIMessage response;
    try {
      response = new GeneralPKIMessage(encodedResponse);
    } catch (IOException ex) {
      LOG.error("could not decode the received PKI message: {}", Hex.encode(encodedResponse));
      throw new CmpRequestorException(ex.getMessage(), ex);
    }

    PKIHeader reqHeader = request.getHeader();
    PKIHeader respHeader = response.getHeader();

    ASN1OctetString tid = reqHeader.getTransactionID();
    ASN1OctetString respTid = respHeader.getTransactionID();
    if (!tid.equals(respTid)) {
      LOG.warn("Response contains different tid ({}) than requested {}", respTid, tid);
      throw new CmpRequestorException("Response contains differnt tid than the request");
    }

    ASN1OctetString senderNonce = reqHeader.getSenderNonce();
    ASN1OctetString respRecipientNonce = respHeader.getRecipNonce();
    if (!senderNonce.equals(respRecipientNonce)) {
      LOG.warn("tid {}: response.recipientNonce ({}) != request.senderNonce ({})",
          tid, respRecipientNonce, senderNonce);
      throw new CmpRequestorException("Response contains differnt tid than the request");
    }

    GeneralName rec = respHeader.getRecipient();
    if (!sender.equals(rec)) {
      LOG.warn("tid={}: unknown CMP requestor '{}'", tid, rec);
    }

    PkiResponse ret = new PkiResponse(response);
    if (response.hasProtection()) {
      try {
        ProtectionVerificationResult verifyProtection = verifyProtection(
            Hex.encode(tid.getOctets()), response);
        ret.setProtectionVerificationResult(verifyProtection);
      } catch (InvalidKeyException | OperatorCreationException | CMPException ex) {
        throw new CmpRequestorException(ex.getMessage(), ex);
      }
    } else if (signRequest) {
      PKIBody respBody = response.getBody();
      int bodyType = respBody.getType();
      if (bodyType != PKIBody.TYPE_ERROR) {
        throw new CmpRequestorException("response is not signed");
      }
    }

    return ret;
  } // method signAndSend

  protected ASN1Encodable extractGeneralRepContent(PkiResponse response, String expectedType)
      throws CmpRequestorException, PkiErrorException {
    ParamUtil.requireNonNull("response", response);
    ParamUtil.requireNonNull("expectedType", expectedType);
    return extractGeneralRepContent(response, expectedType, true);
  }

  private ASN1Encodable extractGeneralRepContent(PkiResponse response, String expectedType,
      boolean requireProtectionCheck) throws CmpRequestorException, PkiErrorException {
    ParamUtil.requireNonNull("response", response);
    ParamUtil.requireNonNull("expectedType", expectedType);
    if (requireProtectionCheck) {
      checkProtection(response);
    }

    PKIBody respBody = response.getPkiMessage().getBody();
    int bodyType = respBody.getType();

    if (PKIBody.TYPE_ERROR == bodyType) {
      ErrorMsgContent content = ErrorMsgContent.getInstance(respBody.getContent());
      throw new CmpRequestorException(CmpFailureUtil.formatPkiStatusInfo(
          content.getPKIStatusInfo()));
    } else if (PKIBody.TYPE_GEN_REP != bodyType) {
      throw new CmpRequestorException(String.format(
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
      throw new CmpRequestorException("the response does not contain InfoTypeAndValue "
          + expectedType);
    }

    return itv.getInfoValue();
  } // method extractGeneralRepContent

  protected ASN1Encodable extractXipkiActionRepContent(PkiResponse response, int action)
      throws CmpRequestorException, PkiErrorException {
    ParamUtil.requireNonNull("response", response);
    ASN1Encodable itvValue = extractGeneralRepContent(response,
        ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId(), true);
    return extractXiActionContent(itvValue, action);
  }

  protected ASN1Encodable extractXiActionContent(ASN1Encodable itvValue, int action)
      throws CmpRequestorException {
    ParamUtil.requireNonNull("itvValue", itvValue);
    ASN1Sequence seq;
    try {
      seq = ASN1Sequence.getInstance(itvValue);
    } catch (IllegalArgumentException ex) {
      throw new CmpRequestorException("invalid syntax of the response");
    }

    int size = seq.size();
    if (size != 1 && size != 2) {
      throw new CmpRequestorException("invalid syntax of the response");
    }

    int tmpAction;
    try {
      tmpAction = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue().intValue();
    } catch (IllegalArgumentException ex) {
      throw new CmpRequestorException("invalid syntax of the response");
    }

    if (action != tmpAction) {
      throw new CmpRequestorException("received XiPKI action '" + tmpAction
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

    PKIHeaderBuilder hdrBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, sender, recipient);
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

    if (protectedMsg.hasPasswordBasedMacProtection()) {
      LOG.warn("NOT_SIGNAUTRE_BASED: {}",
          pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
      return new ProtectionVerificationResult(null, ProtectionResult.NOT_SIGNATURE_BASED);
    }

    PKIHeader header = protectedMsg.getHeader();

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

    AlgorithmIdentifier protectionAlgo = protectedMsg.getHeader().getProtectionAlg();
    if (!responder.getSigAlgoValidator().isAlgorithmPermitted(protectionAlgo)) {
      String algoName;
      try {
        algoName = AlgorithmUtil.getSignatureAlgoName(protectionAlgo);
      } catch (NoSuchAlgorithmException ex) {
        algoName = protectionAlgo.getAlgorithm().getId();
      }
      LOG.warn("tid={}: response protected by untrusted protection algorithm '{}'", tid, algoName);
      return new ProtectionVerificationResult(null, ProtectionResult.INVALID);
    }

    X509Certificate cert = responder.getCert();
    ContentVerifierProvider verifierProvider = securityFactory.getContentVerifierProvider(cert);
    if (verifierProvider == null) {
      LOG.warn("tid={}: not authorized responder '{}'", tid, header.getSender());
      return new ProtectionVerificationResult(cert, ProtectionResult.SENDER_NOT_AUTHORIZED);
    }

    boolean signatureValid = protectedMsg.verify(verifierProvider);
    ProtectionResult protRes = signatureValid ? ProtectionResult.VALID : ProtectionResult.INVALID;
    return new ProtectionVerificationResult(cert, protRes);
  } // method verifyProtection

  protected PKIMessage buildMessageWithXipkAction(int action, ASN1Encodable value)
      throws CmpRequestorException {
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
      ASN1Encodable value) throws CmpRequestorException {
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

    if (protectionVerificationResult == null
        || protectionVerificationResult.getProtectionResult() != ProtectionResult.VALID) {
      throw new PkiErrorException(ClientErrorCode.PKISTATUS_RESPONSE_ERROR,
          PKIFailureInfo.badMessageCheck, "message check of the response failed");
    }
  }

  public boolean isSendRequestorCert() {
    return sendRequestorCert;
  }

  public void setSendRequestorCert(boolean sendRequestorCert) {
    this.sendRequestorCert = sendRequestorCert;
  }

  public boolean isSignRequest() {
    return signRequest;
  }

  public void setSignRequest(boolean signRequest) {
    this.signRequest = signRequest;
  }

  protected byte[] decrypt(EncryptedValue ev) throws XiSecurityException {
    if (requestor == null) {
      throw new XiSecurityException("requestor is null");
    }

    if (!(requestor.getSigningKey() instanceof PrivateKey)) {
      throw new XiSecurityException("no decryption key is configured");
    }

    return decrypt(ev, (PrivateKey) requestor.getSigningKey());
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
      if (!(symmAlg.getAlgorithm().equals(CMSAlgorithm.AES128_CBC)
          || symmAlg.getAlgorithm().equals(CMSAlgorithm.AES192_CBC)
          || symmAlg.getAlgorithm().equals(CMSAlgorithm.AES256_CBC))) {
        // currently we only support AES128-CBC
        throw new XiSecurityException("unsupported symmAlg " + symmAlg.getAlgorithm().getId());
      }

      Cipher dataCipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
      /*
       * As defined in §4.1 in RFC 3565:
       * The AlgorithmIdentifier parameters field MUST be present, and the
       * parameters field MUST contain a AES-IV:
       *
       *     AES-IV ::= OCTET STRING (SIZE(16))
       */
      byte[] iv = DEROctetString.getInstance(symmAlg.getParameters()).getOctets();
      AlgorithmParameterSpec algParams = new IvParameterSpec(iv);
      dataCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(symmKey, "AES"), algParams);

      byte[] encValue = ev.getEncValue().getOctets();
      return dataCipher.doFinal(encValue);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
        | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
      throw new XiSecurityException("Error while decrypting the EncryptedValue", ex);
    }
  }

}
