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

package org.xipki.ca.server.cmp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.InsufficientPermissionException;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.RequestorInfo.CmpRequestorInfo;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.server.CaInfo;
import org.xipki.ca.server.DhpocControl;
import org.xipki.ca.server.X509Ca;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.*;
import org.xipki.security.cmp.CmpUtil;
import org.xipki.security.cmp.ProtectionResult;
import org.xipki.security.cmp.ProtectionVerificationResult;
import org.xipki.util.Base64;
import org.xipki.util.*;
import org.xipki.util.concurrent.ConcurrentBag;
import org.xipki.util.concurrent.ConcurrentBagEntry;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.xipki.ca.server.CaAuditConstants.*;
import static org.xipki.util.Args.notNull;

/**
 * Base CMP responder.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class BaseCmpResponder {

  private static final Logger LOG = LoggerFactory.getLogger(BaseCmpResponder.class);

  private static final int PVNO_CMP2000 = 2;

  protected static final Set<String> KNOWN_GENMSG_IDS = new HashSet<>();

  private static final AlgorithmIdentifier prf_hmacWithSHA256 =
      SignAlgo.HMAC_SHA256.getAlgorithmIdentifier();

  private static final ConcurrentBag<ConcurrentBagEntry<Cipher>> aesGcm_ciphers;

  private static final ConcurrentBag<ConcurrentBagEntry<SecretKeyFactory>> pbkdf2_kdfs;

  private static final Map<ErrorCode, Integer> errorCodeToPkiFailureMap = new HashMap<>(20);

  private static final boolean aesGcm_ciphers_initialized;

  private static final boolean pbkdf2_kdfs_initialized;

  protected static final Set<String> kupCertExtnIds;

  private final SecurityFactory securityFactory;

  private final SecureRandom random = new SecureRandom();

  private final String caName;

  protected final CaManagerImpl caManager;

  private final KeyGenerator aesKeyGen;

  static {
    KNOWN_GENMSG_IDS.add(CMPObjectIdentifiers.it_currentCRL.getId());
    KNOWN_GENMSG_IDS.add(ObjectIdentifiers.Xipki.id_xipki_cmp_cmpGenmsg.getId());

    String oid = NISTObjectIdentifiers.id_aes128_GCM.getId();
    aesGcm_ciphers = new ConcurrentBag<>();
    for (int i = 0; i < 64; i++) {
      Cipher cipher;
      try {
        cipher = Cipher.getInstance(oid);
      } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
        LogUtil.error(LOG, ex, "could not get Cipher of " + oid);
        break;
      }
      aesGcm_ciphers.add(new ConcurrentBagEntry<>(cipher));
    }
    int size = aesGcm_ciphers.size();
    aesGcm_ciphers_initialized = size > 0;
    if (size > 0) {
      LOG.info("initialized {} AES GCM Cipher instances", size);
    } else {
      LOG.error("could not initialize any AES GCM Cipher instance");
    }

    oid = PKCSObjectIdentifiers.id_PBKDF2.getId();
    pbkdf2_kdfs = new ConcurrentBag<>();
    for (int i = 0; i < 64; i++) {
      SecretKeyFactory keyFact;
      try {
        keyFact = SecretKeyFactory.getInstance(oid);
      } catch (NoSuchAlgorithmException ex) {
        LogUtil.error(LOG, ex, "could not get SecretKeyFactory of " + oid);
        break;
      }
      pbkdf2_kdfs.add(new ConcurrentBagEntry<>(keyFact));
    }

    size = pbkdf2_kdfs.size();
    pbkdf2_kdfs_initialized = size > 0;
    if (size > 0) {
      LOG.info("initialized {} PBKDF2 SecretKeyFactory instances", size);
    } else {
      LOG.error("could not initialize any PBKDF2 SecretKeyFactory instance");
    }

    kupCertExtnIds = new HashSet<>();
    kupCertExtnIds.add(Extension.biometricInfo.getId());
    kupCertExtnIds.add(Extension.extendedKeyUsage.getId());
    kupCertExtnIds.add(Extension.keyUsage.getId());
    kupCertExtnIds.add(Extension.qCStatements.getId());
    kupCertExtnIds.add(Extension.subjectAlternativeName.getId());
    kupCertExtnIds.add(Extension.subjectInfoAccess.getId());

    errorCodeToPkiFailureMap.put(ErrorCode.ALREADY_ISSUED,       PKIFailureInfo.badRequest);
    errorCodeToPkiFailureMap.put(ErrorCode.BAD_CERT_TEMPLATE,    PKIFailureInfo.badCertTemplate);
    errorCodeToPkiFailureMap.put(ErrorCode.BAD_REQUEST,          PKIFailureInfo.badRequest);
    errorCodeToPkiFailureMap.put(ErrorCode.CERT_REVOKED,         PKIFailureInfo.certRevoked);
    errorCodeToPkiFailureMap.put(ErrorCode.CERT_UNREVOKED,       PKIFailureInfo.notAuthorized);
    errorCodeToPkiFailureMap.put(ErrorCode.BAD_POP,              PKIFailureInfo.badPOP);
    errorCodeToPkiFailureMap.put(ErrorCode.NOT_PERMITTED,        PKIFailureInfo.notAuthorized);
    errorCodeToPkiFailureMap.put(ErrorCode.INVALID_EXTENSION,    PKIFailureInfo.badRequest);
    errorCodeToPkiFailureMap.put(ErrorCode.SYSTEM_UNAVAILABLE,   PKIFailureInfo.systemUnavail);
    errorCodeToPkiFailureMap.put(ErrorCode.UNKNOWN_CERT,         PKIFailureInfo.badCertId);
    errorCodeToPkiFailureMap.put(ErrorCode.UNKNOWN_CERT_PROFILE, PKIFailureInfo.badCertTemplate);
  }

  protected BaseCmpResponder(CaManagerImpl caManager, String caName)
      throws NoSuchAlgorithmException {
    this.caManager = caManager;
    this.caName = caName;
    this.securityFactory = caManager.getSecurityFactory();
    this.aesKeyGen = KeyGenerator.getInstance("AES");
  }

  protected abstract PKIBody cmpEnrollCert(String dfltCertprofileName,
      PKIMessage request, PKIHeaderBuilder respHeader, CmpControl cmpControl, PKIHeader reqHeader,
      PKIBody reqBody, CmpRequestorInfo requestor, ASN1OctetString tid, String msgId,
      AuditEvent event) throws InsufficientPermissionException;

  protected abstract PKIBody cmpUnRevokeRemoveCertificates(PKIMessage request,
      PKIHeaderBuilder respHeader, CmpControl cmpControl, PKIHeader reqHeader, PKIBody reqBody,
      CmpRequestorInfo requestor, String msgId, AuditEvent event);

  protected abstract PKIBody cmpGeneralMsg(PKIHeaderBuilder respHeader, CmpControl cmpControl,
      PKIHeader reqHeader, PKIBody reqBody, CmpRequestorInfo requestor, ASN1OctetString tid,
      String msgId, AuditEvent event) throws InsufficientPermissionException;

  protected abstract PKIBody confirmCertificates(ASN1OctetString transactionId,
      CertConfirmContent certConf, String msgId);

  protected abstract boolean revokePendingCertificates(ASN1OctetString transactionId, String msgId);

  private ConcurrentContentSigner getSigner() {
    String name = getResponderName();
    return caManager.getSignerWrapper(name).getSigner();
  }

  private GeneralName getSender() {
    return caManager.getSignerWrapper(getResponderName()).getSubjectAsGeneralName();
  }

  private boolean intendsMe(GeneralName requestRecipient) {
    if (requestRecipient == null) {
      return false;
    }

    if (getSender().equals(requestRecipient)) {
      return true;
    }

    if (requestRecipient.getTagNo() == GeneralName.directoryName) {
      X500Name x500Name = X500Name.getInstance(requestRecipient.getName());
      if (x500Name.equals(caManager.getSignerWrapper(getResponderName()).getSubject())) {
        return true;
      }

      return x500Name.equals(getCa().getCaCert().getSubject());
    }

    return false;
  }

  public X509Ca getCa() {
    try {
      return caManager.getX509Ca(caName);
    } catch (CaMgmtException ex) {
      throw new IllegalStateException(ex.getMessage(), ex);
    }
  }

  public boolean isOnService() {
    boolean onService;
    try {
      onService = getSigner() != null;
    } catch (Exception ex) {
      LogUtil.error(LOG, ex, "could not get responder signer");
      return false;
    }

    if (!onService) {
      return false;
    }

    CaInfo caInfo = getCa().getCaInfo();
    return caInfo.getStatus() == CaStatus.ACTIVE && caInfo.supportsCmp();
  } // method isOnService

  public HealthCheckResult healthCheck() {
    HealthCheckResult result = getCa().healthCheck();

    boolean healthy = result.isHealthy();

    boolean responderHealthy =
        caManager.getSignerWrapper(getResponderName()).getSigner().isHealthy();
    healthy &= responderHealthy;

    HealthCheckResult responderHealth = new HealthCheckResult();
    responderHealth.setName("Responder");
    responderHealth.setHealthy(responderHealthy);
    result.addChildCheck(responderHealth);

    result.setHealthy(healthy);
    return result;
  }

  public String getCaName() {
    return caName;
  }

  private String getResponderName() {
    return getCa().getCaInfo().getCmpResponderName();
  }

  /**
   * Get the CMP control.
   *
   * @return never returns {@code null}.
   */
  private CmpControl getCmpControl() {
    return getCa().getCmpControl();
  }

  // CHECKSTYLE:SKIP
  private CmpRequestorInfo getMacRequestor(byte[] senderKID) {
    return getCa().getMacRequestor(senderKID);
  }

  private CmpRequestorInfo getRequestor(X500Name requestorSender) {
    return getCa().getRequestor(requestorSender);
  }

  private static X500Name getX500Sender(PKIHeader reqHeader) {
    GeneralName requestSender = reqHeader.getSender();
    if (requestSender.getTagNo() != GeneralName.directoryName) {
      return null;
    }

    return (X500Name) requestSender.getName();
  } // method getX500Sender

  /**
   * Processes the request and returns the response.
   * @param request
   *          Original request. Will only be used for the storage. Could be{@code null}.
   * @param requestor
   *          Requestor. Must not be {@code null}.
   * @param tid
   *          Transaction id. Must not be {@code null}.
   * @param message
   *          PKI message. Must not be {@code null}.
   * @param msgId
   *          Message id. Must not be {@code null}.
   * @param parameters
   *          Additional parameters.
   * @param event
   *          Audit event. Must not be {@code null}.
   * @return the response
   */
  private PKIMessage processPkiMessage0(PKIMessage request, RequestorInfo requestor,
      ASN1OctetString tid, GeneralPKIMessage message, String msgId,
      Map<String, String> parameters, AuditEvent event) {
    if (!(requestor instanceof CmpRequestorInfo)) {
      throw new IllegalArgumentException(
          "unknown requestor type " + requestor.getClass().getName());
    }

    CmpRequestorInfo cmpRequestor = (CmpRequestorInfo) requestor;
    event.addEventData(NAME_requestor, cmpRequestor.getIdent().getName());

    PKIHeader reqHeader = message.getHeader();
    PKIHeaderBuilder respHeader = new PKIHeaderBuilder(
        reqHeader.getPvno().getValue().intValue(), getSender(), reqHeader.getSender());
    respHeader.setTransactionID(tid);
    ASN1OctetString senderNonce = reqHeader.getSenderNonce();
    if (senderNonce != null) {
      respHeader.setRecipNonce(senderNonce);
    }

    PKIBody respBody;
    PKIBody reqBody = message.getBody();
    final int type = reqBody.getType();

    CmpControl cmpControl = getCmpControl();

    try {
      if (type == PKIBody.TYPE_INIT_REQ || type == PKIBody.TYPE_CERT_REQ
          || type == PKIBody.TYPE_KEY_UPDATE_REQ || type == PKIBody.TYPE_P10_CERT_REQ
          || type == PKIBody.TYPE_CROSS_CERT_REQ) {
        String eventType;

        if (PKIBody.TYPE_CERT_REQ == type) {
          eventType = Cmp.TYPE_cr;
        } else if (PKIBody.TYPE_INIT_REQ == type) {
          eventType = Cmp.TYPE_ir;
        } else if (PKIBody.TYPE_KEY_UPDATE_REQ == type) {
          eventType = Cmp.TYPE_kur;
        } else if (PKIBody.TYPE_P10_CERT_REQ == type) {
          eventType = Cmp.TYPE_p10cr;
        } else {// if (PKIBody.TYPE_CROSS_CERT_REQ == type) {
          eventType = Cmp.TYPE_ccr;
        }

        event.addEventType(eventType);

        String dfltCertprofileName = null;
        if (parameters != null) {
          dfltCertprofileName = parameters.get("certprofile");
        }

        respBody = cmpEnrollCert(dfltCertprofileName, request, respHeader,
            cmpControl, reqHeader, reqBody, cmpRequestor, tid, msgId, event);
      } else if (type == PKIBody.TYPE_CERT_CONFIRM) {
        event.addEventType(Cmp.TYPE_certConf);
        CertConfirmContent certConf = (CertConfirmContent) reqBody.getContent();
        respBody = confirmCertificates(tid, certConf, msgId);
      } else if (type == PKIBody.TYPE_REVOCATION_REQ) {
        respBody = cmpUnRevokeRemoveCertificates(request, respHeader, cmpControl, reqHeader,
            reqBody, cmpRequestor, msgId, event);
      } else if (type == PKIBody.TYPE_CONFIRM) {
        event.addEventType(Cmp.TYPE_pkiconf);
        respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
      } else if (type == PKIBody.TYPE_GEN_MSG) {
        respBody = cmpGeneralMsg(respHeader, cmpControl, reqHeader, reqBody, cmpRequestor,
            tid, msgId, event);
      } else if (type == PKIBody.TYPE_ERROR) {
        event.addEventType(Cmp.TYPE_error);
        revokePendingCertificates(tid, msgId);
        respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
      } else {
        event.addEventType("PKIBody." + type);
        respBody = buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
            "unsupported type " + type);
      }
    } catch (InsufficientPermissionException ex) {
      ErrorMsgContent emc = new ErrorMsgContent(
          new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(ex.getMessage()),
              new PKIFailureInfo(PKIFailureInfo.notAuthorized)));

      respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
    }

    if (respBody.getType() == PKIBody.TYPE_ERROR) {
      ErrorMsgContent errorMsgContent = (ErrorMsgContent) respBody.getContent();

      org.xipki.security.cmp.PkiStatusInfo pkiStatus =
          new org.xipki.security.cmp.PkiStatusInfo(errorMsgContent.getPKIStatusInfo());

      event.setStatus(AuditStatus.FAILED);
      String statusString = pkiStatus.statusMessage();
      if (statusString != null) {
        event.addEventData(NAME_message, statusString);
      }
    } else if (event.getStatus() == null) {
      event.setStatus(AuditStatus.SUCCESSFUL);
    }

    return new PKIMessage(respHeader.build(), respBody);
  } // method processPKIMessage0

  public PKIMessage processPkiMessage(PKIMessage pkiMessage, X509Cert tlsClientCert,
      Map<String, String> parameters, AuditEvent event) {
    notNull(pkiMessage, "pkiMessage");
    notNull(event, "event");
    GeneralPKIMessage message = new GeneralPKIMessage(pkiMessage);

    PKIHeader reqHeader = message.getHeader();
    ASN1OctetString tid = reqHeader.getTransactionID();

    String msgId = RandomUtil.nextHexLong();
    event.addEventData(NAME_mid, msgId);

    if (tid == null) {
      byte[] randomBytes = randomTransactionId();
      tid = new DEROctetString(randomBytes);
    }
    String tidStr = Base64.encodeToString(tid.getOctets());
    event.addEventData(NAME_tid, tidStr);

    int reqPvno = reqHeader.getPvno().getValue().intValue();
    if (reqPvno < PVNO_CMP2000) {
      event.update(AuditLevel.INFO, AuditStatus.FAILED);
      event.addEventData(NAME_message, "unsupported version " + reqPvno);
      return buildErrorPkiMessage(tid, reqHeader, PKIFailureInfo.unsupportedVersion, null);
    }

    CmpControl cmpControl = getCmpControl();

    Integer failureCode = null;
    String statusText = null;

    Date messageTime = null;
    if (reqHeader.getMessageTime() != null) {
      try {
        messageTime = reqHeader.getMessageTime().getDate();
      } catch (ParseException ex) {
        LogUtil.error(LOG, ex, "tid=" + tidStr + ": could not parse messageTime");
      }
    }

    GeneralName recipient = reqHeader.getRecipient();
    boolean intentMe = recipient == null || intendsMe(recipient);
    if (!intentMe) {
      LOG.warn("tid={}: I am not the intended recipient, but '{}'", tid, reqHeader.getRecipient());
      failureCode = PKIFailureInfo.badRequest;
      statusText = "I am not the intended recipient";
    } else if (messageTime == null) {
      if (cmpControl.isMessageTimeRequired()) {
        failureCode = PKIFailureInfo.missingTimeStamp;
        statusText = "missing time-stamp";
      }
    } else {
      long messageTimeBias = cmpControl.getMessageTimeBias();
      if (messageTimeBias < 0) {
        messageTimeBias *= -1;
      }

      long msgTimeMs = messageTime.getTime();
      long currentTimeMs = System.currentTimeMillis();
      long bias = (msgTimeMs - currentTimeMs) / 1000L;
      if (bias > messageTimeBias) {
        failureCode = PKIFailureInfo.badTime;
        statusText = "message time is in the future";
      } else if (bias * -1 > messageTimeBias) {
        failureCode = PKIFailureInfo.badTime;
        statusText = "message too old";
      }
    }

    if (failureCode != null) {
      event.update(AuditLevel.INFO, AuditStatus.FAILED);
      event.addEventData(NAME_message, statusText);
      return buildErrorPkiMessage(tid, reqHeader, failureCode, statusText);
    }

    boolean isProtected = message.hasProtection();
    CmpRequestorInfo requestor;

    String errorStatus;

    if (isProtected) {
      try {
        ProtectionVerificationResult verificationResult = verifyProtection(tidStr,
            message, cmpControl);
        ProtectionResult pr = verificationResult.getProtectionResult();
        if (pr == ProtectionResult.SIGNATURE_VALID || pr == ProtectionResult.MAC_VALID) {
          errorStatus = null;
        } else if (pr == ProtectionResult.SIGNATURE_INVALID) {
          errorStatus = "request is protected by signature but invalid";
        } else if (pr == ProtectionResult.MAC_INVALID) {
          errorStatus = "request is protected by MAC but invalid";
        } else if (pr == ProtectionResult.SENDER_NOT_AUTHORIZED) {
          errorStatus = "request is protected but the requestor is not authorized";
        } else if (pr == ProtectionResult.SIGNATURE_ALGO_FORBIDDEN) {
          errorStatus = "request is protected by signature but the algorithm is forbidden";
        } else if (pr == ProtectionResult.MAC_ALGO_FORBIDDEN) {
          errorStatus = "request is protected by MAC but the algorithm is forbidden";
        } else {
          throw new IllegalStateException("should not reach here, unknown ProtectionResult " + pr);
        }
        requestor = (CmpRequestorInfo) verificationResult.getRequestor();
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "tid=" + tidStr + ": could not verify the signature");
        errorStatus = "request has invalid signature based protection";
        requestor = null;
      }
    } else if (tlsClientCert != null) {
      boolean authorized = false;

      X500Name x500Sender = getX500Sender(reqHeader);
      requestor = (x500Sender == null) ? null : getRequestor(x500Sender);

      if (requestor != null) {
        if (tlsClientCert.equals(requestor.getCert().getCert())) {
          authorized = true;
        }
      }

      if (authorized) {
        errorStatus = null;
      } else {
        LOG.warn("tid={}: not authorized requestor (TLS client '{}')", tid,
            tlsClientCert.getSubjectRfc4519Text());
        errorStatus = "requestor (TLS client certificate) is not authorized";
      }
    } else {
      errorStatus = "request has no protection";
      requestor = null;
    }

    if (errorStatus != null) {
      event.update(AuditLevel.INFO, AuditStatus.FAILED);
      event.addEventData(NAME_message, errorStatus);
      return buildErrorPkiMessage(tid, reqHeader, PKIFailureInfo.badMessageCheck, errorStatus);
    }

    PKIMessage resp = processPkiMessage0(pkiMessage, requestor, tid, message, msgId, parameters,
        event);

    if (isProtected) {
      resp = addProtection(resp, event, requestor);
    }
    // otherwise protected by TLS connection

    return resp;
  } // method processPkiMessage

  private byte[] randomTransactionId() {
    return randomBytes(10);
  }

  private byte[] randomSalt() {
    return randomBytes(64);
  }

  private byte[] randomBytes(int len) {
    byte[] bytes = new byte[len];
    random.nextBytes(bytes);
    return bytes;
  } // method randomBytes

  private ProtectionVerificationResult verifyProtection(String tid, GeneralPKIMessage pkiMessage,
      CmpControl cmpControl)
          throws CMPException, InvalidKeyException {
    ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

    PKIHeader header = protectedMsg.getHeader();
    X500Name sender = getX500Sender(header);
    if (sender == null) {
      LOG.warn("tid={}: not authorized requestor 'null'", tid);
      return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
    }

    AlgorithmIdentifier protectionAlg = header.getProtectionAlg();

    if (protectedMsg.hasPasswordBasedMacProtection()) {
      PBMParameter parameter = PBMParameter.getInstance(
          pkiMessage.getHeader().getProtectionAlg().getParameters());
      HashAlgo owfAlg;
      try {
        owfAlg = HashAlgo.getInstance(parameter.getOwf());
      } catch (NoSuchAlgorithmException ex) {
        LogUtil.warn(LOG, ex);
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }
      if (!cmpControl.isRequestPbmOwfPermitted(owfAlg)) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.owf: {})", owfAlg.getJceName());
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      SignAlgo macAlg;
      try {
        macAlg = SignAlgo.getInstance(parameter.getMac());
      } catch (NoSuchAlgorithmException ex) {
        LogUtil.warn(LOG, ex);
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }
      if (!cmpControl.isRequestPbmMacPermitted(macAlg)) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.mac: {})", macAlg.getJceName());
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      int iterationCount = parameter.getIterationCount().getValue().intValue();
      if (iterationCount < 1000) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.iterationCount: {} < 1000)", iterationCount);
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      ASN1OctetString asn1 = header.getSenderKID();
      // CHECKSTYLE:SKIP
      byte[] senderKID = (asn1 == null) ? null : asn1.getOctets();
      PKMACBuilder pkMacBuilder = new PKMACBuilder(new JcePKMACValuesCalculator());

      CmpRequestorInfo requestor = getMacRequestor(senderKID);

      if (requestor == null) {
        LOG.warn("tid={}: not authorized requestor with senderKID '{}", tid,
            (senderKID == null) ? "null" : Hex.toHexString(senderKID));
        return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      boolean macValid = protectedMsg.verify(pkMacBuilder, requestor.getPassword());
      return new ProtectionVerificationResult(requestor,
          macValid ? ProtectionResult.MAC_VALID : ProtectionResult.MAC_INVALID);
    } else {
      if (!cmpControl.getSigAlgoValidator().isAlgorithmPermitted(protectionAlg)) {
        LOG.warn("SIG_ALGO_FORBIDDEN: {}",
            pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
        return new ProtectionVerificationResult(null, ProtectionResult.SIGNATURE_ALGO_FORBIDDEN);
      }

      X500Name x500Sender = getX500Sender(header);
      CmpRequestorInfo requestor = (x500Sender == null) ? null : getRequestor(x500Sender);
      if (requestor == null) {
        LOG.warn("tid={}: not authorized requestor '{}'", tid, header.getSender());
        return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      ContentVerifierProvider verifierProvider = securityFactory.getContentVerifierProvider(
          requestor.getCert().getCert());
      if (verifierProvider == null) {
        LOG.warn("tid={}: not authorized requestor '{}'", tid, sender);
        return new ProtectionVerificationResult(requestor,
            ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      boolean signatureValid = protectedMsg.verify(verifierProvider);
      return new ProtectionVerificationResult(requestor,
          signatureValid ? ProtectionResult.SIGNATURE_VALID : ProtectionResult.SIGNATURE_INVALID);
    }
  } // method verifyProtection

  private PKIMessage addProtection(PKIMessage pkiMessage, AuditEvent event,
      CmpRequestorInfo requestor) {
    CmpControl control = getCmpControl();
    try {
      if (requestor.getCert() != null) {
        return CmpUtil.addProtection(pkiMessage, getSigner(), getSender(),
            control.isSendResponderCert());
      }

      PBMParameter parameter = new PBMParameter(randomSalt(),
          control.getResponsePbmOwf().getAlgorithmIdentifier(),
          control.getResponsePbmIterationCount(),
          control.getResponsePbmMac().getAlgorithmIdentifier());
      return CmpUtil.addProtection(pkiMessage, requestor.getPassword(), parameter,
          getSender(), requestor.getKeyId());
    } catch (Exception ex) {
      LogUtil.error(LOG, ex, "could not add protection to the PKI message");
      PKIStatusInfo status = generateRejectionStatus(
          PKIFailureInfo.systemFailure, "could not sign the PKIMessage");

      event.update(AuditLevel.ERROR, AuditStatus.FAILED);
      event.addEventData(NAME_message, "could not sign the PKIMessage");
      PKIBody body = new PKIBody(PKIBody.TYPE_ERROR, new ErrorMsgContent(status));
      return new PKIMessage(pkiMessage.getHeader(), body);
    }
  } // method addProtection

  private PKIMessage buildErrorPkiMessage(ASN1OctetString tid,
      PKIHeader requestHeader, int failureCode, String statusText) {
    GeneralName respRecipient = requestHeader.getSender();

    PKIHeaderBuilder respHeader = new PKIHeaderBuilder(
        requestHeader.getPvno().getValue().intValue(), getSender(), respRecipient);
    respHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
    if (tid != null) {
      respHeader.setTransactionID(tid);
    }

    ASN1OctetString senderNonce = requestHeader.getSenderNonce();
    if (senderNonce != null) {
      respHeader.setRecipNonce(senderNonce);
    }

    PKIStatusInfo status = generateRejectionStatus(failureCode, statusText);
    ErrorMsgContent error = new ErrorMsgContent(status);
    PKIBody body = new PKIBody(PKIBody.TYPE_ERROR, error);

    return new PKIMessage(respHeader.build(), body);
  } // method buildErrorPkiMessage

  protected static PKIStatusInfo generateRejectionStatus(Integer info, String errorMessage) {
    return generateRejectionStatus(PKIStatus.rejection, info, errorMessage);
  } // method generateCmpRejectionStatus

  protected static PKIStatusInfo generateRejectionStatus(PKIStatus status, Integer info,
      String errorMessage) {
    PKIFreeText statusMessage = (errorMessage == null) ? null : new PKIFreeText(errorMessage);
    PKIFailureInfo failureInfo = (info == null) ? null : new PKIFailureInfo(info);
    return new PKIStatusInfo(status, statusMessage, failureInfo);
  } // method generateCmpRejectionStatus

  protected static int getPKiFailureInfo(OperationException ex) {
    Integer failureInfo = errorCodeToPkiFailureMap.get(ex.getErrorCode());
    return failureInfo == null ? PKIFailureInfo.systemFailure : failureInfo;
  }

  protected String getSystemInfo(CmpRequestorInfo requestor, Set<Integer> acceptVersions)
      throws OperationException {
    X509Ca ca = getCa();
    CaInfo caInfo = ca.getCaInfo();

    // current only version 3 is supported
    int version = 3;
    if (acceptVersions != null && !acceptVersions.contains(version)) {
      throw new OperationException(ErrorCode.BAD_REQUEST,
          "none of versions " + acceptVersions + " is supported");
    }

    JSONObject root = new JSONObject(false);
    root.put("version", version);
    List<byte[]> certchain = new LinkedList<>();

    certchain.add(caInfo.getCert().getEncoded());
    for (X509Cert m : caInfo.getCertchain()) {
      certchain.add(m.getEncoded());
    }
    root.put("caCertchain", certchain);

    JSONObject jsonCmpControl = new JSONObject(false);
    jsonCmpControl.put("rrAkiRequired", getCmpControl().isRrAkiRequired());
    root.put("cmpControl", jsonCmpControl);

    // Profiles
    Set<String> requestorProfiles = requestor.getCaHasRequestor().getProfiles();
    Set<String> supportedProfileNames = new HashSet<>();
    Set<String> caProfileNames =
        ca.getCaManager().getCertprofilesForCa(caInfo.getIdent().getName());
    for (String caProfileName : caProfileNames) {
      if (requestorProfiles.contains("all") || requestorProfiles.contains(caProfileName)) {
        supportedProfileNames.add(caProfileName);
      }
    }

    if (CollectionUtil.isNotEmpty(supportedProfileNames)) {
      List<JSONObject> jsonCertprofiles = new LinkedList<>();
      root.put("certprofiles", jsonCertprofiles);
      for (String name : supportedProfileNames) {
        CertprofileEntry entry = ca.getCaManager().getCertprofile(name);
        if (entry.isFaulty()) {
          continue;
        }

        JSONObject jsonCertprofile = new JSONObject(false);
        jsonCertprofile.put("name", name);
        jsonCertprofile.put("type", entry.getType());
        jsonCertprofile.put("conf", entry.getConf());
        jsonCertprofiles.add(jsonCertprofile);
      }
    }

    // DHPocs
    DhpocControl dhpocControl = ca.getCaInfo().getDhpocControl();
    if (dhpocControl != null) {
      X509Cert[] certs = dhpocControl.getCertificates();
      List<byte[]> dhpocCerts = new LinkedList<>();
      for (X509Cert m : certs) {
        dhpocCerts.add(m.getEncoded());
      }
      root.put("dhpocs", dhpocCerts);
    }

    return JSON.toJSONString(root, false);
  } // method getSystemInfo

  protected void checkPermission(CmpRequestorInfo requestor, int requiredPermission)
      throws InsufficientPermissionException {
    X509Ca ca = getCa();
    int permission = ca.getCaInfo().getPermission();
    if (!PermissionConstants.contains(permission, requiredPermission)) {
      throw new InsufficientPermissionException("Permission "
          + PermissionConstants.getTextForCode(requiredPermission) + "is not permitted");
    }

    requestor.assertPermitted(requiredPermission);
  } // method checkPermission

  protected static PKIBody buildErrorMsgPkiBody(PKIStatus pkiStatus, int failureInfo,
      String statusMessage) {
    PKIFreeText pkiStatusMsg = (statusMessage == null) ? null : new PKIFreeText(statusMessage);
    ErrorMsgContent emc = new ErrorMsgContent(
        new PKIStatusInfo(pkiStatus, pkiStatusMsg, new PKIFailureInfo(failureInfo)));
    return new PKIBody(PKIBody.TYPE_ERROR, emc);
  }

  protected static CertResponse buildErrCertResp(ASN1Integer certReqId, int pkiFailureInfo,
      String pkiStatusText) {
    return new CertResponse(certReqId, generateRejectionStatus(pkiFailureInfo, pkiStatusText));
  }

  protected static void addErrCertResp(List<CertResponse> resps, ASN1Integer certReqId,
      int pkiFailureInfo, String pkiStatusText) {
    resps.add(new CertResponse(certReqId, generateRejectionStatus(pkiFailureInfo, pkiStatusText)));
  }

  protected boolean verifyPopo(CertificateRequestMessage certRequest, SubjectPublicKeyInfo spki,
      boolean allowRaPopo) {
    int popType = certRequest.getProofOfPossessionType();
    if (popType == CertificateRequestMessage.popRaVerified && allowRaPopo) {
      return true;
    }

    if (popType != CertificateRequestMessage.popSigningKey) {
      LOG.error("unsupported POP type: " + popType);
      return false;
    }

    // check the POP signature algorithm
    ProofOfPossession pop = certRequest.toASN1Structure().getPopo();
    POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());
    SignAlgo popoAlg;
    try {
      popoAlg = SignAlgo.getInstance(popoSign.getAlgorithmIdentifier());
    } catch (NoSuchAlgorithmException ex) {
      LogUtil.error(LOG, ex, "Cannot parse POPO signature algorithm");
      return false;
    }

    AlgorithmValidator algoValidator = getCmpControl().getPopoAlgoValidator();
    if (!algoValidator.isAlgorithmPermitted(popoAlg)) {
      LOG.error("POPO signature algorithm {} not permitted", popoAlg.getJceName());
      return false;
    }

    try {
      PublicKey publicKey = securityFactory.generatePublicKey(spki);
      DhpocControl dhpocControl = getCa().getCaInfo().getDhpocControl();

      DHSigStaticKeyCertPair kaKeyAndCert = null;
      if (SignAlgo.DHPOP_X25519 == popoAlg || SignAlgo.DHPOP_X448 == popoAlg) {
        if (dhpocControl != null) {
          DhSigStatic dhSigStatic = DhSigStatic.getInstance(popoSign.getSignature().getBytes());
          IssuerAndSerialNumber isn = dhSigStatic.getIssuerAndSerial();

          ASN1ObjectIdentifier keyAlgOid = spki.getAlgorithm().getAlgorithm();
          kaKeyAndCert = dhpocControl.getKeyCertPair(isn.getName(),
              isn.getSerialNumber().getValue(), EdECConstants.getName(keyAlgOid));
        }

        if (kaKeyAndCert == null) {
          return false;
        }
      }

      ContentVerifierProvider cvp = securityFactory.getContentVerifierProvider(
          publicKey, kaKeyAndCert);
      return certRequest.isValidSigningKeyPOP(cvp);
    } catch (InvalidKeyException | IllegalStateException | CRMFException ex) {
      LogUtil.error(LOG, ex);
    }
    return false;
  } // method verifyPopo

  protected static CertResponse postProcessException(ASN1Integer certReqId, OperationException ex) {
    ErrorCode code = ex.getErrorCode();
    LOG.warn("generate certificate, OperationException: code={}, message={}",
        code.name(), ex.getErrorMessage());

    String errorMessage;
    if (code == ErrorCode.DATABASE_FAILURE || code == ErrorCode.SYSTEM_FAILURE) {
      errorMessage = code.name();
    } else {
      errorMessage = code.name() + ": " + ex.getErrorMessage();
    } // end switch code

    int failureInfo = getPKiFailureInfo(ex);
    return new CertResponse(certReqId, generateRejectionStatus(failureInfo, errorMessage));
  }

  protected CertResponse postProcessCertInfo(ASN1Integer certReqId, CmpRequestorInfo requestor,
      CertificateInfo certInfo) {
    String warningMsg = certInfo.getWarningMessage();

    PKIStatusInfo statusInfo;
    if (StringUtil.isBlank(warningMsg)) {
      statusInfo = certInfo.isAlreadyIssued()
          ? new PKIStatusInfo(PKIStatus.grantedWithMods, new PKIFreeText("ALREADY_ISSUED"))
          : new PKIStatusInfo(PKIStatus.granted);
    } else {
      statusInfo = new PKIStatusInfo(PKIStatus.grantedWithMods,
          new PKIFreeText(warningMsg));
    }

    CertOrEncCert cec = new CertOrEncCert(
        new CMPCertificate(certInfo.getCert().getCert().toBcCert().toASN1Structure()));
    if (certInfo.getPrivateKey() == null) {
      // no private key will be returned.
      return new CertResponse(certReqId, statusInfo, new CertifiedKeyPair(cec), null);
    }

    final int aesGcmTagByteLen = 16;
    final int aesGcmNonceLen = 12;

    PrivateKeyInfo privKey = certInfo.getPrivateKey();
    AlgorithmIdentifier intendedAlg = privKey.getPrivateKeyAlgorithm();
    EncryptedValue encKey;

    // Due to the bug mentioned in https://github.com/bcgit/bc-java/issues/359
    // we cannot use BoucyCastle's EncryptedValueBuilder to build the EncryptedValue.
    try {
      if (requestor.getCert() != null) {
        // use private key of the requestor to encrypt the private key
        PublicKey reqPub = requestor.getCert().getCert().getPublicKey();
        CrmfKeyWrapper wrapper;
        if (reqPub instanceof RSAPublicKey) {
          wrapper = new CrmfKeyWrapper.RSAOAEPAsymmetricKeyWrapper(reqPub);
        } else if (reqPub instanceof ECPublicKey) {
          wrapper = new CrmfKeyWrapper.ECIESAsymmetricKeyWrapper(reqPub);
        } else {
          String msg = "Requestors's private key can not be used for encryption";
          LOG.error(msg);
          return new CertResponse(certReqId,
              new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(msg)));
        }

        byte[] symmKeyBytes;
        synchronized (aesKeyGen) {
          symmKeyBytes = aesKeyGen.generateKey().getEncoded();
        }

        // encrypt the symmKey
        byte[] encSymmKey = wrapper.generateWrappedKey(symmKeyBytes);
        // algorithmIdentifier after the encryption process.
        AlgorithmIdentifier keyAlg = wrapper.getAlgorithmIdentifier();

        // encrypt the data
        ASN1ObjectIdentifier symmAlgOid = NISTObjectIdentifiers.id_aes128_GCM;
        byte[] nonce = randomBytes(aesGcmNonceLen);

        ConcurrentBagEntry<Cipher> cipher0 = null;
        if (aesGcm_ciphers_initialized) {
          try {
            cipher0 = aesGcm_ciphers.borrow(5, TimeUnit.SECONDS);
          } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
          }
        }

        Cipher dataCipher = (cipher0 != null)
            ? cipher0.value() : Cipher.getInstance(symmAlgOid.getId());

        byte[] encValue;

        try {
          try {
            dataCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(symmKeyBytes, "AES"),
                new GCMParameterSpec(aesGcmTagByteLen << 3, nonce));
          } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new IllegalStateException(ex);
          }

          encValue = dataCipher.doFinal(privKey.getEncoded());
        } finally {
          if (cipher0 != null) {
            aesGcm_ciphers.requite(cipher0);
          }
        }

        GCMParameters params = new GCMParameters(nonce, aesGcmTagByteLen);
        AlgorithmIdentifier symmAlg = new AlgorithmIdentifier(symmAlgOid, params);

        encKey = new EncryptedValue(intendedAlg, symmAlg,
            new DERBitString(encSymmKey), keyAlg, null, new DERBitString(encValue));
      } else {
        final ASN1ObjectIdentifier encAlgOid = NISTObjectIdentifiers.id_aes128_GCM;
        final int keysizeBits = 128; // one of 128, 192 and 256. Must match the encAlgOid
        final int iterCount = 10240; // >= 1000
        final int nonceLen = 12; // fixed value
        final int tagByteLen = 16; // fixed value

        byte[] nonce = randomBytes(nonceLen);

        // use password of the requestor to encrypt the private key
        byte[] pbkdfSalt = randomBytes(keysizeBits / 8);

        ConcurrentBagEntry<SecretKeyFactory> keyFact0 = null;
        if (pbkdf2_kdfs_initialized) {
          try {
            keyFact0 = pbkdf2_kdfs.borrow(5, TimeUnit.SECONDS);
          } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
          }
        }

        SecretKeyFactory keyFact = (keyFact0 != null) ? keyFact0.value()
            : SecretKeyFactory.getInstance(PKCSObjectIdentifiers.id_PBKDF2.getId());

        SecretKey key;

        try {
          key = keyFact.generateSecret(new PBKDF2KeySpec(requestor.getPassword(), pbkdfSalt,
                  iterCount, keysizeBits, prf_hmacWithSHA256));
          key = new SecretKeySpec(key.getEncoded(), "AES");
        } finally {
          if (keyFact0 != null) {
            pbkdf2_kdfs.requite(keyFact0);
          }
        }

        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(tagByteLen * 8, nonce);

        ConcurrentBagEntry<Cipher> cipher0 = null;
        if (aesGcm_ciphers_initialized) {
          try {
            cipher0 = aesGcm_ciphers.borrow(5, TimeUnit.SECONDS);
          } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
          }
        }

        Cipher dataCipher = (cipher0 != null)
            ? cipher0.value() : Cipher.getInstance(encAlgOid.getId());

        byte[] encValue;
        try {
          dataCipher.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec);
          encValue = dataCipher.doFinal(privKey.getEncoded());
        } finally {
          if (cipher0 != null) {
            aesGcm_ciphers.requite(cipher0);
          }
        }

        AlgorithmIdentifier symmAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2,
            new PBES2Parameters(
                new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2,
                    new PBKDF2Params(pbkdfSalt, iterCount, keysizeBits / 8, prf_hmacWithSHA256)),
                new EncryptionScheme(encAlgOid, new GCMParameters(nonce, tagByteLen))));

        encKey = new EncryptedValue(intendedAlg, symmAlg,
            null, null, null, new DERBitString(encValue));
      }
    } catch (Throwable th) {
      String msg = "error while encrypting the private key";
      LOG.error(msg);
      return new CertResponse(certReqId,
          new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(msg)));
    }

    return new CertResponse(certReqId, statusInfo, new CertifiedKeyPair(cec, encKey, null), null);
  }

}
