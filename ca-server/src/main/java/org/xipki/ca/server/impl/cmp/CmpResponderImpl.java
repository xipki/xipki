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

package org.xipki.ca.server.impl.cmp;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContentBuilder;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.InsuffientPermissionException;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.server.api.CaAuditConstants;
import org.xipki.ca.server.impl.CaManagerImpl;
import org.xipki.ca.server.impl.CertTemplateData;
import org.xipki.ca.server.impl.X509Ca;
import org.xipki.ca.server.impl.store.CertWithRevocationInfo;
import org.xipki.ca.server.impl.util.CaUtil;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.api.PermissionConstants;
import org.xipki.ca.server.mgmt.api.RequestorInfo;
import org.xipki.cmp.CmpUtf8Pairs;
import org.xipki.cmp.CmpUtil;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.CrlReason;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.XiSecurityConstants;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.DateUtil;
import org.xipki.util.HealthCheckResult;
import org.xipki.util.Hex;
import org.xipki.util.LogUtil;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.concurrent.ConcurrentBag;
import org.xipki.util.concurrent.ConcurrentBagEntry;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpResponderImpl extends BaseCmpResponder {

  private class PendingPoolCleaner implements Runnable {

    @Override
    public void run() {
      Set<CertificateInfo> remainingCerts =
          pendingCertPool.removeConfirmTimeoutedCertificates();

      if (CollectionUtil.isEmpty(remainingCerts)) {
        return;
      }

      Date invalidityDate = new Date();
      X509Ca ca = getCa();
      for (CertificateInfo remainingCert : remainingCerts) {
        BigInteger serialNumber = null;
        try {
          serialNumber = remainingCert.getCert().getCert().getSerialNumber();
          ca.revokeCert(serialNumber, CrlReason.CESSATION_OF_OPERATION,
              invalidityDate, CaAuditConstants.MSGID_ca_routine);
        } catch (Throwable th) {
          LOG.error("could not revoke certificate (CA={}, serialNumber={}): {}",
              ca.getCaInfo().getIdent(), LogUtil.formatCsn(serialNumber), th.getMessage());
        }
      }
    } // method run

  } // class PendingPoolCleaner

  private static final Set<String> KNOWN_GENMSG_IDS = new HashSet<>();

  private static final Logger LOG = LoggerFactory.getLogger(CmpResponderImpl.class);

  private static final AlgorithmIdentifier prf_hmacWithSHA256 =
      new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE);

  private static final ConcurrentBag<ConcurrentBagEntry<Cipher>> aesGcm_ciphers;

  private static final ConcurrentBag<ConcurrentBagEntry<SecretKeyFactory>> pbkdf2_kdfs;

  private static boolean aesGcm_ciphers_initialized;

  private static boolean pbkdf2_kdfs_initialized;

  private final PendingCertificatePool pendingCertPool;

  private final KeyGenerator aesKeyGen;

  private final String caName;

  private final CaManagerImpl caManager;

  static {
    KNOWN_GENMSG_IDS.add(CMPObjectIdentifiers.it_currentCRL.getId());
    KNOWN_GENMSG_IDS.add(ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId());
    KNOWN_GENMSG_IDS.add(ObjectIdentifiers.id_xipki_cmp_cacerts.getId());

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
      aesGcm_ciphers.add(new ConcurrentBagEntry<Cipher>(cipher));
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
      pbkdf2_kdfs.add(new ConcurrentBagEntry<SecretKeyFactory>(keyFact));
    }

    size = pbkdf2_kdfs.size();
    pbkdf2_kdfs_initialized = size > 0;
    if (size > 0) {
      LOG.info("initialized {} PBKDF2 SecretKeyFactory instances", size);
    } else {
      LOG.error("could not initialize any PBKDF2 SecretKeyFactory instance");
    }
  }

  public CmpResponderImpl(CaManagerImpl caManager, String caName)
      throws NoSuchAlgorithmException {
    super(caManager.getSecurityFactory());

    this.aesKeyGen = KeyGenerator.getInstance("AES");
    this.caManager = caManager;
    this.pendingCertPool = new PendingCertificatePool();
    this.caName = caName;

    PendingPoolCleaner pendingPoolCleaner = new PendingPoolCleaner();
    caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(pendingPoolCleaner, 10, 10,
        TimeUnit.MINUTES);
  }

  public X509Ca getCa() {
    try {
      return caManager.getX509Ca(caName);
    } catch (CaMgmtException ex) {
      throw new IllegalStateException(ex.getMessage(), ex);
    }
  }

  @Override
  public boolean isOnService() {
    if (!super.isOnService()) {
      return false;
    }

    if (CaStatus.ACTIVE != getCa().getCaInfo().getStatus()) {
      return false;
    }

    return true;
  }

  public HealthCheckResult healthCheck() {
    HealthCheckResult result = getCa().healthCheck();

    boolean healthy = result.isHealthy();

    boolean responderHealthy =
        caManager.getSignerWrapper(getResponderName()).getSigner().isHealthy();
    healthy &= responderHealthy;

    HealthCheckResult responderHealth = new HealthCheckResult("Responder");
    responderHealth.setHealthy(responderHealthy);
    result.addChildCheck(responderHealth);

    result.setHealthy(healthy);
    return result;
  }

  @Override
  public String getCaName() {
    return caName;
  }

  public String getResponderName() {
    return getCa().getCaInfo().getCmpResponderName();
  }

  @Override
  protected PKIMessage processPkiMessage0(PKIMessage request, RequestorInfo requestor,
      ASN1OctetString tid, GeneralPKIMessage message, String msgId,
      Map<String, String> parameters, AuditEvent event) {
    if (!(requestor instanceof CmpRequestorInfo)) {
      throw new IllegalArgumentException(
          "unknown requestor type " + requestor.getClass().getName());
    }

    CmpRequestorInfo cmpRequestor = (CmpRequestorInfo) requestor;
    event.addEventData(CaAuditConstants.NAME_requestor, cmpRequestor.getIdent().getName());

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
      switch (type) {
        case PKIBody.TYPE_INIT_REQ:
        case PKIBody.TYPE_CERT_REQ:
        case PKIBody.TYPE_KEY_UPDATE_REQ:
        case PKIBody.TYPE_P10_CERT_REQ:
        case PKIBody.TYPE_CROSS_CERT_REQ:
          String eventType = null;
          if (PKIBody.TYPE_CERT_REQ == type) {
            eventType = CaAuditConstants.TYPE_CMP_cr;
          } else if (PKIBody.TYPE_INIT_REQ == type) {
            eventType = CaAuditConstants.TYPE_CMP_ir;
          } else if (PKIBody.TYPE_KEY_UPDATE_REQ == type) {
            eventType = CaAuditConstants.TYPE_CMP_kur;
          } else if (PKIBody.TYPE_P10_CERT_REQ == type) {
            eventType = CaAuditConstants.TYPE_CMP_p10cr;
          } else if (PKIBody.TYPE_CROSS_CERT_REQ == type) {
            eventType = CaAuditConstants.TYPE_CMP_ccr;
          }

          if (eventType != null) {
            event.addEventType(eventType);
          }

          String dfltCertprofileName = (parameters == null) ? null : parameters.get("certprofile");
          String dfltKeyGenType = (parameters == null) ? null : parameters.get("generatekey");
          respBody = cmpEnrollCert(dfltCertprofileName, dfltKeyGenType, request, respHeader,
              cmpControl, reqHeader, reqBody, cmpRequestor, tid, msgId, event);
          break;
        case PKIBody.TYPE_CERT_CONFIRM:
          event.addEventType(CaAuditConstants.TYPE_CMP_certConf);
          CertConfirmContent certConf = (CertConfirmContent) reqBody.getContent();
          respBody = confirmCertificates(tid, certConf, msgId);
          break;
        case PKIBody.TYPE_REVOCATION_REQ:
          respBody = cmpUnRevokeRemoveCertificates(request, respHeader, cmpControl, reqHeader,
              reqBody, cmpRequestor, msgId, event);
          break;
        case PKIBody.TYPE_CONFIRM:
          event.addEventType(CaAuditConstants.TYPE_CMP_pkiconf);
          respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
          break;
        case PKIBody.TYPE_GEN_MSG:
          respBody = cmpGeneralMsg(respHeader, cmpControl, reqHeader, reqBody, cmpRequestor,
              tid, msgId, event);
          break;
        case PKIBody.TYPE_ERROR:
          event.addEventType(CaAuditConstants.TYPE_CMP_error);
          revokePendingCertificates(tid, msgId);
          respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
          break;
        default:
          event.addEventType("PKIBody." + type);
          respBody = buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
              "unsupported type " + type);
          break;
      } // end switch (type)
    } catch (InsuffientPermissionException ex) {
      ErrorMsgContent emc = new ErrorMsgContent(
          new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(ex.getMessage()),
              new PKIFailureInfo(PKIFailureInfo.notAuthorized)));

      respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
    }

    if (respBody.getType() == PKIBody.TYPE_ERROR) {
      ErrorMsgContent errorMsgContent = (ErrorMsgContent) respBody.getContent();

      org.xipki.cmp.PkiStatusInfo pkiStatus =
          new org.xipki.cmp.PkiStatusInfo(errorMsgContent.getPKIStatusInfo());

      event.setStatus(AuditStatus.FAILED);
      String statusString = pkiStatus.statusMessage();
      if (statusString != null) {
        event.addEventData(CaAuditConstants.NAME_message, statusString);
      }
    } else if (event.getStatus() == null) {
      event.setStatus(AuditStatus.SUCCESSFUL);
    }

    return new PKIMessage(respHeader.build(), respBody);
  } // method processPKIMessage0

  private PKIBody processIr(String dfltCertprofileName, String dfltKeyGenType, PKIMessage request,
      CmpRequestorInfo requestor, ASN1OctetString tid, PKIHeader reqHeader, CertReqMessages cr,
      CmpControl cmpControl, String msgId, AuditEvent event) throws InsuffientPermissionException {
    CertRepMessage repMessage = processCertReqMessages(dfltCertprofileName, dfltKeyGenType, request,
        requestor, tid, reqHeader, cr, false, true, cmpControl, msgId, event);
    return new PKIBody(PKIBody.TYPE_INIT_REP, repMessage);
  }

  private PKIBody processCr(String dfltCertprofileName, String dfltKeyGenType, PKIMessage request,
      CmpRequestorInfo requestor, ASN1OctetString tid, PKIHeader reqHeader, CertReqMessages cr,
      CmpControl cmpControl, String msgId, AuditEvent event) throws InsuffientPermissionException {
    CertRepMessage repMessage = processCertReqMessages(dfltCertprofileName, dfltKeyGenType, request,
        requestor, tid, reqHeader, cr, false, true, cmpControl, msgId, event);
    return new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
  }

  private PKIBody processKur(String dfltCertprofileName, String dfltKeyGenType, PKIMessage request,
      CmpRequestorInfo requestor, ASN1OctetString tid, PKIHeader reqHeader, CertReqMessages kur,
      CmpControl cmpControl, String msgId, AuditEvent event) throws InsuffientPermissionException {
    CertRepMessage repMessage = processCertReqMessages(dfltCertprofileName, dfltKeyGenType, request,
        requestor, tid, reqHeader, kur, true, true, cmpControl, msgId, event);
    return new PKIBody(PKIBody.TYPE_KEY_UPDATE_REP, repMessage);
  }

  private PKIBody processCcp(String dfltCertprofileName, PKIMessage request,
      CmpRequestorInfo requestor, ASN1OctetString tid, PKIHeader reqHeader, CertReqMessages cr,
      CmpControl cmpControl, String msgId, AuditEvent event) throws InsuffientPermissionException {
    CertRepMessage repMessage = processCertReqMessages(dfltCertprofileName, null, request,
        requestor, tid, reqHeader, cr, false, false, cmpControl, msgId, event);
    return new PKIBody(PKIBody.TYPE_CROSS_CERT_REP, repMessage);
  }

  private CertRepMessage processCertReqMessages(String dfltCertprofileName, String dfltKeyGenType,
      PKIMessage request, CmpRequestorInfo requestor, ASN1OctetString tid, PKIHeader reqHeader,
      CertReqMessages cr, boolean keyUpdate, boolean allowKeyGen, CmpControl cmpControl,
      String msgId, AuditEvent event) throws InsuffientPermissionException {
    CmpRequestorInfo tmpRequestor = (CmpRequestorInfo) requestor;

    CertReqMsg[] certReqMsgs = cr.toCertReqMsgArray();
    final int n = certReqMsgs.length;

    List<CertTemplateData> certTemplateDatas = new ArrayList<>(n);
    List<CertResponse> certResponses = new ArrayList<>(1);

    // pre-process requests
    for (int i = 0; i < n; i++) {
      if (cmpControl.isGroupEnroll() && certTemplateDatas.size() != i) {
        // last certReqMsg cannot be used to enroll certificate
        break;
      }

      CertReqMsg reqMsg = certReqMsgs[i];
      ASN1Integer certReqId = reqMsg.getCertReq().getCertReqId();

      CmpUtf8Pairs keyvalues = CmpUtil.extract(reqMsg.getRegInfo());
      String certprofileName = (keyvalues == null) ? null
          : keyvalues.value(CmpUtf8Pairs.KEY_CERTPROFILE);
      if (certprofileName == null) {
        certprofileName = dfltCertprofileName;
      }

      if (certprofileName == null) {
        LOG.warn("no certprofile is specified");
        certResponses.add(buildErrorCertResponse(
                            certReqId, PKIFailureInfo.badCertTemplate, "no certificate profile"));
        continue;
      }
      certprofileName = certprofileName.toLowerCase();

      if (!tmpRequestor.isCertprofilePermitted(certprofileName)) {
        String msg = "certprofile " + certprofileName + " is not allowed";
        certResponses.add(buildErrorCertResponse(certReqId, PKIFailureInfo.notAuthorized, msg));
        continue;
      }

      CertificateRequestMessage req = new CertificateRequestMessage(reqMsg);

      if (req.getCertTemplate().getPublicKey() != null) {
        if (!req.hasProofOfPossession()) {
          certResponses.add(buildErrorCertResponse(certReqId, PKIFailureInfo.badPOP, "no POP"));
          continue;
        }

        if (!verifyPopo(req, tmpRequestor.isRa())) {
          LOG.warn("could not validate POP for request {}", certReqId.getValue());
          certResponses.add(buildErrorCertResponse(certReqId, PKIFailureInfo.badPOP,
              "invalid POP"));
          continue;
        }
      } else {
        if (allowKeyGen) {
          checkPermission(requestor, PermissionConstants.GEN_KEYPAIR);
        } else {
          LOG.warn("no public key is specified and key generation is not allowed {}",
              certReqId.getValue());
          certResponses.add(buildErrorCertResponse(certReqId, PKIFailureInfo.badCertTemplate,
              "no public key"));
          continue;
        }
      }

      CertTemplate certTemp = req.getCertTemplate();
      OptionalValidity validity = certTemp.getValidity();

      Date notBefore = null;
      Date notAfter = null;
      if (validity != null) {
        Time time = validity.getNotBefore();
        if (time != null) {
          notBefore = time.getDate();
        }
        time = validity.getNotAfter();
        if (time != null) {
          notAfter = time.getDate();
        }
      }

      CertTemplateData certTempData = new CertTemplateData(certTemp.getSubject(),
          certTemp.getPublicKey(), notBefore, notAfter,  certTemp.getExtensions(), certprofileName,
          certReqId);
      certTemplateDatas.add(certTempData);
    } // end for

    if (certResponses.size() == n) {
      // all error
      CertResponse[] certResps = new CertResponse[n];
      for (int i = 0; i < n; i++) {
        certResps[i] = certResponses.get(i);
      }
      event.setStatus(AuditStatus.FAILED);
      return new CertRepMessage(null, certResps);
    }

    if (cmpControl.isGroupEnroll() && certTemplateDatas.size() != n) {
      event.setStatus(AuditStatus.FAILED);
      // GroupEnroll and at least one certRequest cannot be used to enroll certificate
      int lastFailureIndex = certTemplateDatas.size();
      BigInteger failCertReqId =
          certReqMsgs[lastFailureIndex].getCertReq().getCertReqId().getValue();
      CertResponse failCertResp = certResponses.get(lastFailureIndex);
      PKIStatus failStatus = PKIStatus.getInstance(
          new ASN1Integer(failCertResp.getStatus().getStatus()));
      PKIFailureInfo failureInfo = new PKIFailureInfo(failCertResp.getStatus().getFailInfo());

      CertResponse[] certResps = new CertResponse[n];

      for (int i = 0; i < n; i++) {
        if (i == lastFailureIndex) {
          certResps[i] = failCertResp;
          continue;
        }

        ASN1Integer certReqId = certResps[i].getCertReqId();
        String msg = "error in certReq " + failCertReqId;
        PKIStatusInfo tmpStatus = generateRejectionStatus(failStatus, failureInfo.intValue(), msg);
        certResps[i] = new CertResponse(certReqId, tmpStatus);
      }

      return new CertRepMessage(null, certResps);
    }

    List<CertResponse> generateCertResponses = generateCertificates(certTemplateDatas, tmpRequestor,
        tid, keyUpdate, request, cmpControl, msgId, event);

    CertResponse[] certResps = new CertResponse[n];
    int index = 0;
    for (CertResponse errorResp : certResponses) {
      // error single CertResponse
      certResps[index++] = errorResp;
    }

    for (CertResponse certResp : generateCertResponses) {
      certResps[index++] = certResp;
    }

    CMPCertificate[] caPubs = null;
    if (cmpControl.isSendCaCert()) {
      boolean anyCertEnrolled = false;
      for (CertResponse certResp : generateCertResponses) {
        if (certResp.getCertifiedKeyPair() != null) {
          anyCertEnrolled = true;
          break;
        }
      }
      if (anyCertEnrolled && cmpControl.isSendCaCert()) {
        caPubs = new CMPCertificate[]{getCa().getCaInfo().getCertInCmpFormat()};
      }
    }

    return new CertRepMessage(caPubs, certResps);
  } // method processCertReqMessages

  /**
   * handle the PKI body with the choice {@code p10cr}<br/>
   * Since it is not possible to add attribute to the PKCS#10 request (CSR), the certificate
   * profile must be specified in the attribute regInfo-utf8Pairs (1.3.6.1.5.5.7.5.2.1) within
   * PKIHeader.generalInfo
   *
   */
  private PKIBody processP10cr(String dfltCertprofileName, PKIMessage request,
      CmpRequestorInfo requestor, ASN1OctetString tid, PKIHeader reqHeader,
      CertificationRequest p10cr, CmpControl cmpControl, String msgId, AuditEvent event) {
    // verify the POP first
    CertResponse certResp;
    ASN1Integer certReqId = new ASN1Integer(-1);

    boolean certGenerated = false;
    X509Ca ca = getCa();

    if (!securityFactory.verifyPopo(p10cr, getCmpControl().getPopoAlgoValidator())) {
      LOG.warn("could not validate POP for the pkcs#10 requst");
      certResp = buildErrorCertResponse(certReqId, PKIFailureInfo.badPOP, "invalid POP");
    } else {
      CertificationRequestInfo certTemp = p10cr.getCertificationRequestInfo();
      Extensions extensions = CaUtil.getExtensions(certTemp);

      X500Name subject = certTemp.getSubject();
      SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();

      CmpUtf8Pairs keyvalues = CmpUtil.extract(reqHeader.getGeneralInfo());
      Date notBefore = null;
      Date notAfter = null;
      String certprofileName = null;
      if (keyvalues != null) {
        certprofileName = keyvalues.value(CmpUtf8Pairs.KEY_CERTPROFILE);

        String str = keyvalues.value(CmpUtf8Pairs.KEY_NOTBEFORE);
        if (str != null) {
          notBefore = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
        }

        str = keyvalues.value(CmpUtf8Pairs.KEY_NOTAFTER);
        if (str != null) {
          notAfter = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
        }
      }

      if (certprofileName == null) {
        certprofileName = dfltCertprofileName;
      }

      if (certprofileName == null) {
        LOG.warn("no certprofile is specified");
        certResp = buildErrorCertResponse(certReqId, PKIFailureInfo.badCertTemplate,
            "badCertTemplate");
      } else {
        certprofileName = certprofileName.toLowerCase();
        if (!requestor.isCertprofilePermitted(certprofileName)) {
          String msg = "certprofile " + certprofileName + " is not allowed";
          certResp = buildErrorCertResponse(certReqId, PKIFailureInfo.notAuthorized, msg);
        } else {
          CertTemplateData certTemplateData = new CertTemplateData(subject, publicKeyInfo,
              notBefore, notAfter, extensions, certprofileName, certReqId);

          certResp = generateCertificates(Arrays.asList(certTemplateData),
              requestor, tid, false, request, cmpControl, msgId, event).get(0);
          certGenerated = true;
        }
      }
    }

    CMPCertificate[] caPubs = null;
    if (certGenerated && cmpControl.isSendCaCert()) {
      caPubs = new CMPCertificate[]{ca.getCaInfo().getCertInCmpFormat()};
    }

    if (event.getStatus() == null || event.getStatus() != AuditStatus.FAILED) {
      int status = certResp.getStatus().getStatus().intValue();
      if (status != PKIStatus.GRANTED && status != PKIStatus.GRANTED_WITH_MODS
          && status != PKIStatus.WAITING) {
        event.setStatus(AuditStatus.FAILED);
        PKIFreeText statusStr = certResp.getStatus().getStatusString();
        if (statusStr != null) {
          event.addEventData(CaAuditConstants.NAME_message, statusStr.getStringAt(0).getString());
        }
      }
    }

    CertRepMessage repMessage = new CertRepMessage(caPubs, new CertResponse[]{certResp});

    return new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
  } // method processP10cr

  private List<CertResponse> generateCertificates(List<CertTemplateData> certTemplates,
      CmpRequestorInfo requestor, ASN1OctetString tid, boolean keyUpdate, PKIMessage request,
      CmpControl cmpControl, String msgId, AuditEvent event) {
    X509Ca ca = getCa();

    final int n = certTemplates.size();
    List<CertResponse> ret = new ArrayList<>(n);

    if (cmpControl.isGroupEnroll()) {
      List<CertificateInfo> certInfos = null;
      try {
        if (keyUpdate) {
          certInfos = ca.regenerateCerts(certTemplates, requestor, RequestType.CMP,
              tid.getOctets(), msgId);
        } else {
          certInfos = ca.generateCerts(certTemplates, requestor, RequestType.CMP,
              tid.getOctets(), msgId);
        }

        // save the request
        Long reqDbId = null;
        if (ca.getCaInfo().isSaveRequest()) {
          try {
            byte[] encodedRequest = request.getEncoded();
            reqDbId = ca.addRequest(encodedRequest);
          } catch (Exception ex) {
            LOG.warn("could not save request");
          }
        }

        for (int i = 0; i < n; i++) {
          CertificateInfo certInfo = certInfos.get(i);
          ret.add(postProcessCertInfo(certTemplates.get(i).getCertReqId(), requestor, certInfo, tid,
              cmpControl));
          if (reqDbId != null) {
            ca.addRequestCert(reqDbId, certInfo.getCert().getCertId());
          }
        }
      } catch (OperationException ex) {
        if (certInfos != null) {
          for (CertificateInfo certInfo : certInfos) {
            BigInteger sn = certInfo.getCert().getCertHolder().getSerialNumber();
            try {
              ca.revokeCert(sn, CrlReason.CESSATION_OF_OPERATION, null, msgId);
            } catch (OperationException ex2) {
              LogUtil.error(LOG, ex2, "CA " + getCaName() + " could not revoke certificate " + sn);
            }
          }
        }
        event.setStatus(AuditStatus.FAILED);
        ret.clear();
        for (int i = 0; i < n; i++) {
          ret.add(postProcessException(certTemplates.get(i).getCertReqId(), ex));
        }
      }
    } else {
      Long reqDbId = null;
      boolean savingRequestFailed = false;

      for (int i = 0; i < n; i++) {
        CertTemplateData certTemplate = certTemplates.get(i);
        ASN1Integer certReqId = certTemplate.getCertReqId();

        CertificateInfo certInfo;
        try {
          if (keyUpdate) {
            certInfo = ca.regenerateCert(certTemplate, requestor, RequestType.CMP,
                tid.getOctets(), msgId);
          } else {
            certInfo = ca.generateCert(certTemplate, requestor, RequestType.CMP,
                tid.getOctets(), msgId);
          }

          if (ca.getCaInfo().isSaveRequest()) {
            if (reqDbId == null && !savingRequestFailed) {
              try {
                byte[] encodedRequest = request.getEncoded();
                reqDbId = ca.addRequest(encodedRequest);
              } catch (Exception ex) {
                savingRequestFailed = true;
                LOG.warn("could not save request");
              }
            }

            if (reqDbId != null) {
              ca.addRequestCert(reqDbId, certInfo.getCert().getCertId());
            }
          }

          CertResponse certResponse =
              postProcessCertInfo(certReqId, requestor, certInfo, tid, cmpControl);
          ret.add(certResponse);
        } catch (OperationException ex) {
          event.setStatus(AuditStatus.FAILED);
          ret.add(postProcessException(certReqId, ex));
        }
      }
    }

    return ret;
  } // method generateCertificates

  private CertResponse postProcessCertInfo(ASN1Integer certReqId, CmpRequestorInfo requestor,
      CertificateInfo certInfo, ASN1OctetString tid, CmpControl cmpControl) {
    if (cmpControl.isConfirmCert()) {
      pendingCertPool.addCertificate(tid.getOctets(), certReqId.getPositiveValue(), certInfo,
          System.currentTimeMillis() + cmpControl.getConfirmWaitTimeMs());
    }

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
        CMPCertificate.getInstance(certInfo.getCert().getEncodedCert()));
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
        // use public key of the requestor to encrypt the private key
        PublicKey reqPub = requestor.getCert().getCert().getPublicKey();
        CrmfKeyWrapper wrapper = null;
        if (reqPub instanceof RSAPublicKey) {
          wrapper = new CrmfKeyWrapper.RSAOAEPAsymmetricKeyWrapper(reqPub);
        } else if (reqPub instanceof ECPublicKey) {
          wrapper = new CrmfKeyWrapper.ECIESAsymmetricKeyWrapper(reqPub);
        } else {
          String msg = "Requestors's public key can not be used for encryption";
          LOG.error(msg);
          return new CertResponse(certReqId,
              new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(msg)));
        }

        byte[] symmKeyBytes = new byte[16];
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
        final int iterationCount = 10240; // >= 1000
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
          key = keyFact.generateSecret(
              new PBKDF2KeySpec(requestor.getPassword(), pbkdfSalt, iterationCount,
                  keysizeBits, prf_hmacWithSHA256));
          byte[] encoded = key.getEncoded();
          key = new SecretKeySpec(encoded, "AES");
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

        byte[] encValue;

        Cipher dataCipher = (cipher0 != null)
            ? cipher0.value() : Cipher.getInstance(encAlgOid.getId());

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
                    new PBKDF2Params(pbkdfSalt, iterationCount, keysizeBits / 8,
                        prf_hmacWithSHA256)),
                new EncryptionScheme(encAlgOid, new GCMParameters(nonce, tagByteLen))));

        encKey = new EncryptedValue(intendedAlg, symmAlg,
            null, null, null, new DERBitString(encValue));
      }
    } catch (Exception ex) {
      String msg = "error while encrypting the private key";
      LOG.error(msg);
      return new CertResponse(certReqId,
          new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(msg)));
    }

    return new CertResponse(certReqId, statusInfo,
        new CertifiedKeyPair(cec, encKey, null), null);
  }

  private PKIBody unRevokeRemoveCertificates(PKIMessage request, RevReqContent rr,
      int permission, CmpControl cmpControl, String msgId, AuditEvent event) {
    RevDetails[] revContent = rr.toRevDetailsArray();

    RevRepContentBuilder repContentBuilder = new RevRepContentBuilder();
    final int n = revContent.length;
    // test the request
    for (int i = 0; i < n; i++) {
      RevDetails revDetails = revContent[i];

      CertTemplate certDetails = revDetails.getCertDetails();
      X500Name issuer = certDetails.getIssuer();
      ASN1Integer serialNumber = certDetails.getSerialNumber();

      try {
        X500Name caSubject = getCa().getCaInfo().getCert().getSubjectAsX500Name();

        if (issuer == null) {
          return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badCertTemplate,
              "issuer is not present");
        }

        if (!issuer.equals(caSubject)) {
          return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badCertTemplate,
              "issuer does not target at the CA");
        }

        if (serialNumber == null) {
          return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badCertTemplate,
              "serialNumber is not present");
        }

        if (certDetails.getSigningAlg() != null   || certDetails.getValidity() != null
            || certDetails.getSubject() != null   || certDetails.getPublicKey() != null
            || certDetails.getIssuerUID() != null || certDetails.getSubjectUID() != null) {
          return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badCertTemplate,
              "only version, issuer and serialNumber in RevDetails.certDetails are "
              + "allowed, but more is specified");
        }

        if (certDetails.getExtensions() == null) {
          if (cmpControl.isRrAkiRequired()) {
            return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badCertTemplate,
                "issuer's AKI not present");
          }
        } else {
          Extensions exts = certDetails.getExtensions();
          ASN1ObjectIdentifier[] oids = exts.getCriticalExtensionOIDs();
          if (oids != null) {
            for (ASN1ObjectIdentifier oid : oids) {
              if (!Extension.authorityKeyIdentifier.equals(oid)) {
                return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badCertTemplate,
                    "unknown critical extension " + oid.getId());
              }
            }
          }

          Extension ext = exts.getExtension(Extension.authorityKeyIdentifier);
          if (ext == null) {
            return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badCertTemplate,
                "issuer's AKI not present");
          } else {
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(ext.getParsedValue());

            if (aki.getKeyIdentifier() == null) {
              return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badCertTemplate,
                  "issuer's AKI not present");
            }

            boolean issuerMatched = true;

            byte[] caSki = getCa().getCaInfo().getCert().getSubjectKeyIdentifier();
            if (!Arrays.equals(caSki, aki.getKeyIdentifier())) {
              issuerMatched = false;
            }

            if (issuerMatched && aki.getAuthorityCertSerialNumber() != null) {
              BigInteger caSerial = getCa().getCaInfo().getSerialNumber();
              if (!caSerial.equals(aki.getAuthorityCertSerialNumber())) {
                issuerMatched = false;
              }
            }

            if (issuerMatched && aki.getAuthorityCertIssuer() != null) {
              GeneralName[] names = aki.getAuthorityCertIssuer().getNames();
              for (GeneralName name : names) {
                if (name.getTagNo() != GeneralName.directoryName) {
                  issuerMatched = false;
                  break;
                }

                if (!caSubject.equals(name.getName())) {
                  issuerMatched = false;
                  break;
                }
              }
            }

            if (!issuerMatched) {
              return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badCertTemplate,
                  "issuer does not target at the CA");
            }
          }
        }
      } catch (IllegalArgumentException ex) {
        return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
            "the request is not invalid");
      }
    } // end for

    byte[] encodedRequest = null;
    if (getCa().getCaInfo().isSaveRequest()) {
      try {
        encodedRequest = request.getEncoded();
      } catch (IOException ex) {
        LOG.warn("could not encode request");
      }
    }

    Long reqDbId = null;

    for (int i = 0; i < n; i++) {
      RevDetails revDetails = revContent[i];

      CertTemplate certDetails = revDetails.getCertDetails();
      ASN1Integer serialNumber = certDetails.getSerialNumber();
      // serialNumber is not null due to the check in the previous for-block.

      X500Name caSubject = getCa().getCaInfo().getCert().getSubjectAsX500Name();
      BigInteger snBigInt = serialNumber.getPositiveValue();
      CertId certId = new CertId(new GeneralName(caSubject), serialNumber);

      PKIStatusInfo status;

      try {
        Object returnedObj = null;
        Long certDbId = null;
        X509Ca ca = getCa();
        if (PermissionConstants.UNREVOKE_CERT == permission) {
          // unrevoke
          returnedObj = ca.unrevokeCert(snBigInt, msgId);
          if (returnedObj != null) {
            certDbId = ((CertWithDbId) returnedObj).getCertId();
          }
        } else if (PermissionConstants.REMOVE_CERT == permission) {
          // remove
          returnedObj = ca.removeCert(snBigInt, msgId);
        } else {
          // revoke
          Date invalidityDate = null;
          CrlReason reason = null;

          Extensions crlDetails = revDetails.getCrlEntryDetails();
          if (crlDetails != null) {
            ASN1ObjectIdentifier extId = Extension.reasonCode;
            ASN1Encodable extValue = crlDetails.getExtensionParsedValue(extId);
            if (extValue != null) {
              int reasonCode = ASN1Enumerated.getInstance(extValue).getValue().intValue();
              reason = CrlReason.forReasonCode(reasonCode);
            }

            extId = Extension.invalidityDate;
            extValue = crlDetails.getExtensionParsedValue(extId);
            if (extValue != null) {
              try {
                invalidityDate = ASN1GeneralizedTime.getInstance(extValue).getDate();
              } catch (ParseException ex) {
                throw new OperationException(ErrorCode.INVALID_EXTENSION,
                    "invalid extension " + extId.getId());
              }
            }
          } // end if (crlDetails)

          if (reason == null) {
            reason = CrlReason.UNSPECIFIED;
          }

          returnedObj = ca.revokeCert(snBigInt, reason, invalidityDate, msgId);
          if (returnedObj != null) {
            certDbId = ((CertWithRevocationInfo) returnedObj).getCert().getCertId();
          }
        } // end if (permission)

        if (returnedObj == null) {
          throw new OperationException(ErrorCode.UNKNOWN_CERT, "cert not exists");
        }

        if (certDbId != null && ca.getCaInfo().isSaveRequest()) {
          if (reqDbId == null) {
            reqDbId = ca.addRequest(encodedRequest);
          }
          ca.addRequestCert(reqDbId, certDbId);
        }
        status = new PKIStatusInfo(PKIStatus.granted);
      } catch (OperationException ex) {
        ErrorCode code = ex.getErrorCode();
        LOG.warn("{}, OperationException: code={}, message={}",
            PermissionConstants.getTextForCode(permission), code.name(), ex.getErrorMessage());
        String errorMessage;
        switch (code) {
          case DATABASE_FAILURE:
          case SYSTEM_FAILURE:
            errorMessage = code.name();
            break;
          default:
            errorMessage = code.name() + ": " + ex.getErrorMessage();
            break;
        } // end switch code

        int failureInfo = getPKiFailureInfo(ex);
        status = generateRejectionStatus(failureInfo, errorMessage);
        event.setLevel(AuditLevel.ERROR);
        event.setStatus(AuditStatus.FAILED);
        event.addEventData(CaAuditConstants.NAME_message, errorMessage);
      } // end try

      repContentBuilder.add(status, certId);
    } // end for

    return new PKIBody(PKIBody.TYPE_REVOCATION_REP, repContentBuilder.build());
  } // method revokeOrUnrevokeOrRemoveCertificates

  private CertResponse postProcessException(ASN1Integer certReqId, OperationException ex) {
    ErrorCode code = ex.getErrorCode();
    LOG.warn("generate certificate, OperationException: code={}, message={}",
        code.name(), ex.getErrorMessage());

    String errorMessage;
    switch (code) {
      case DATABASE_FAILURE:
      case SYSTEM_FAILURE:
        errorMessage = code.name();
        break;
      default:
        errorMessage = code.name() + ": " + ex.getErrorMessage();
        break;
    } // end switch code

    int failureInfo = getPKiFailureInfo(ex);
    return new CertResponse(certReqId, generateRejectionStatus(failureInfo, errorMessage));
  }

  private int getPKiFailureInfo(OperationException ex) {
    ErrorCode code = ex.getErrorCode();

    int failureInfo;
    switch (code) {
      case ALREADY_ISSUED:
        failureInfo = PKIFailureInfo.badRequest;
        break;
      case BAD_CERT_TEMPLATE:
        failureInfo = PKIFailureInfo.badCertTemplate;
        break;
      case BAD_REQUEST:
        failureInfo = PKIFailureInfo.badRequest;
        break;
      case CERT_REVOKED:
        failureInfo = PKIFailureInfo.certRevoked;
        break;
      case CERT_UNREVOKED:
        failureInfo = PKIFailureInfo.notAuthorized;
        break;
      case BAD_POP:
        failureInfo = PKIFailureInfo.badPOP;
        break;
      case CRL_FAILURE:
        failureInfo = PKIFailureInfo.systemFailure;
        break;
      case DATABASE_FAILURE:
        failureInfo = PKIFailureInfo.systemFailure;
        break;
      case NOT_PERMITTED:
        failureInfo = PKIFailureInfo.notAuthorized;
        break;
      case INVALID_EXTENSION:
        failureInfo = PKIFailureInfo.badRequest;
        break;
      case SYSTEM_FAILURE:
        failureInfo = PKIFailureInfo.systemFailure;
        break;
      case SYSTEM_UNAVAILABLE:
        failureInfo = PKIFailureInfo.systemUnavail;
        break;
      case UNKNOWN_CERT:
        failureInfo = PKIFailureInfo.badCertId;
        break;
      case UNKNOWN_CERT_PROFILE:
        failureInfo = PKIFailureInfo.badCertTemplate;
        break;
      default:
        failureInfo = PKIFailureInfo.systemFailure;
        break;
    } // end switch (code)

    return failureInfo;
  }

  private PKIBody confirmCertificates(ASN1OctetString transactionId, CertConfirmContent certConf,
      String msgId) {
    CertStatus[] certStatuses = certConf.toCertStatusArray();

    boolean successful = true;
    for (CertStatus certStatus : certStatuses) {
      ASN1Integer certReqId = certStatus.getCertReqId();
      byte[] certHash = certStatus.getCertHash().getOctets();
      CertificateInfo certInfo = pendingCertPool.removeCertificate(
          transactionId.getOctets(), certReqId.getPositiveValue(), certHash);
      if (certInfo == null) {
        if (LOG.isWarnEnabled()) {
          LOG.warn("no cert under transactionId={}, certReqId={} and certHash=0X{}",
              transactionId, certReqId.getPositiveValue(), Hex.encode(certHash));
        }
        continue;
      }

      PKIStatusInfo statusInfo = certStatus.getStatusInfo();
      boolean accept = true;
      if (statusInfo != null) {
        int status = statusInfo.getStatus().intValue();
        if (PKIStatus.GRANTED != status && PKIStatus.GRANTED_WITH_MODS != status) {
          accept = false;
        }
      }

      if (accept) {
        continue;
      }

      BigInteger serialNumber = certInfo.getCert().getCert().getSerialNumber();
      X509Ca ca = getCa();
      try {
        ca.revokeCert(serialNumber, CrlReason.CESSATION_OF_OPERATION, new Date(), msgId);
      } catch (OperationException ex) {
        LogUtil.warn(LOG, ex, "could not revoke certificate ca=" + ca.getCaInfo().getIdent()
            + " serialNumber=" + LogUtil.formatCsn(serialNumber));
      }

      successful = false;
    }

    // all other certificates should be revoked
    if (revokePendingCertificates(transactionId, msgId)) {
      successful = false;
    }

    if (successful) {
      return new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
    }

    return new PKIBody(PKIBody.TYPE_ERROR,
        new ErrorMsgContent(new PKIStatusInfo(PKIStatus.rejection, null,
                new PKIFailureInfo(PKIFailureInfo.systemFailure))));
  } // method confirmCertificates

  private boolean revokePendingCertificates(ASN1OctetString transactionId, String msgId) {
    Set<CertificateInfo> remainingCerts = pendingCertPool.removeCertificates(
        transactionId.getOctets());

    if (CollectionUtil.isEmpty(remainingCerts)) {
      return true;
    }

    boolean successful = true;
    Date invalidityDate = new Date();
    X509Ca ca = getCa();
    for (CertificateInfo remainingCert : remainingCerts) {
      try {
        ca.revokeCert(remainingCert.getCert().getCert().getSerialNumber(),
            CrlReason.CESSATION_OF_OPERATION, invalidityDate, msgId);
      } catch (OperationException ex) {
        successful = false;
      }
    }

    return successful;
  } // method revokePendingCertificates

  private boolean verifyPopo(CertificateRequestMessage certRequest, boolean allowRaPopo) {
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
    AlgorithmIdentifier popoAlgId = popoSign.getAlgorithmIdentifier();
    AlgorithmValidator algoValidator = getCmpControl().getPopoAlgoValidator();
    if (!algoValidator.isAlgorithmPermitted(popoAlgId)) {
      String algoName;
      try {
        algoName = AlgorithmUtil.getSignatureAlgoName(popoAlgId);
      } catch (NoSuchAlgorithmException ex) {
        algoName = popoAlgId.getAlgorithm().getId();
      }
      LOG.error("POPO signature algorithm {} not permitted", algoName);
      return false;
    }

    try {
      PublicKey publicKey = securityFactory.generatePublicKey(
          certRequest.getCertTemplate().getPublicKey());
      ContentVerifierProvider cvp = securityFactory.getContentVerifierProvider(publicKey);
      return certRequest.isValidSigningKeyPOP(cvp);
    } catch (InvalidKeyException | IllegalStateException | CRMFException ex) {
      LogUtil.error(LOG, ex);
    }
    return false;
  } // method verifyPopo

  @Override
  protected CmpControl getCmpControl() {
    return getCa().getCmpControl();
  }

  private void checkPermission(CmpRequestorInfo requestor, int requiredPermission)
      throws InsuffientPermissionException {
    X509Ca ca = getCa();
    int permission = ca.getCaInfo().getPermission();
    if (!PermissionConstants.contains(permission, requiredPermission)) {
      throw new InsuffientPermissionException("Permission "
          + PermissionConstants.getTextForCode(requiredPermission) + "is not permitted");
    }

    requestor.assertPermitted(requiredPermission);
  } // method checkPermission

  private String getSystemInfo(CmpRequestorInfo requestor, Set<Integer> acceptVersions)
      throws OperationException {
    X509Ca ca = getCa();
    StringBuilder sb = new StringBuilder(2000);
    // current maximal support version is 2
    int version = 2;
    if (CollectionUtil.isNonEmpty(acceptVersions) && !acceptVersions.contains(version)) {
      Integer ver = null;
      for (Integer m : acceptVersions) {
        if (m < version) {
          ver = m;
        }
      }

      if (ver == null) {
        throw new OperationException(ErrorCode.BAD_REQUEST,
          "none of versions " + acceptVersions + " is supported");
      } else {
        version = ver;
      }
    }

    sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
    sb.append("<systemInfo version=\"").append(version).append("\">");
    if (version == 2) {
      // CACert
      sb.append("<CACert>");
      sb.append(Base64.encodeToString(ca.getCaInfo().getCert().getEncodedCert()));
      sb.append("</CACert>");

      // CMP control
      sb.append("<cmpControl>");
      sb.append("<rrAkiRequired>").append(getCmpControl().isRrAkiRequired())
        .append("</rrAkiRequired>");
      sb.append("</cmpControl>");

      // Profiles
      Set<String> requestorProfiles = requestor.getCaHasRequestor().getProfiles();

      Set<String> supportedProfileNames = new HashSet<>();
      Set<String> caProfileNames =
          ca.getCaManager().getCertprofilesForCa(ca.getCaInfo().getIdent().getName());
      for (String caProfileName : caProfileNames) {
        if (requestorProfiles.contains("all") || requestorProfiles.contains(caProfileName)) {
          supportedProfileNames.add(caProfileName);
        }
      }

      if (CollectionUtil.isNonEmpty(supportedProfileNames)) {
        sb.append("<certprofiles>");
        for (String name : supportedProfileNames) {
          CertprofileEntry entry = ca.getCaManager().getCertprofile(name);
          if (entry.isFaulty()) {
            continue;
          }

          sb.append("<certprofile>");
          sb.append("<name>").append(name).append("</name>");
          sb.append("<type>").append(entry.getType()).append("</type>");
          sb.append("<conf>");
          String conf = entry.getConf();
          if (StringUtil.isNotBlank(conf)) {
            sb.append("<![CDATA[");
            sb.append(conf);
            sb.append("]]>");
          }
          sb.append("</conf>");
          sb.append("</certprofile>");
        }

        sb.append("</certprofiles>");
      }

      sb.append("</systemInfo>");
    } else {
      throw new OperationException(ErrorCode.BAD_REQUEST, "unsupported version " + version);
    }

    return sb.toString();
  } // method getSystemInfo

  @Override
  protected ConcurrentContentSigner getSigner() {
    String name = getResponderName();
    return caManager.getSignerWrapper(name).getSigner();
  }

  @Override
  protected GeneralName getSender() {
    return caManager.getSignerWrapper(getResponderName()).getSubjectAsGeneralName();
  }

  @Override
  protected boolean intendsMe(GeneralName requestRecipient) {
    if (requestRecipient == null) {
      return false;
    }

    if (getSender().equals(requestRecipient)) {
      return true;
    }

    if (requestRecipient.getTagNo() == GeneralName.directoryName) {
      X500Name x500Name = X500Name.getInstance(requestRecipient.getName());
      if (x500Name.equals(caManager.getSignerWrapper(getResponderName()).getSubjectAsX500Name())) {
        return true;
      }
    }

    return false;
  } // method intendsMe

  @Override
  public CmpRequestorInfo getRequestor(X500Name requestorSender) {
    return getCa().getRequestor(requestorSender);
  }

  @Override
  public CmpRequestorInfo getRequestor(X509Certificate requestorCert) {
    return getCa().getRequestor(requestorCert);
  }

  @Override
  // CHECKSTYLE:SKIP
  public CmpRequestorInfo getMacRequestor(X500Name requestorSender, byte[] senderKID) {
    return getCa().getMacRequestor(requestorSender, senderKID);
  }

  private PKIBody cmpEnrollCert(String dfltCertprofileName, String dfltKeyGenType,
      PKIMessage request, PKIHeaderBuilder respHeader, CmpControl cmpControl, PKIHeader reqHeader,
      PKIBody reqBody, CmpRequestorInfo requestor, ASN1OctetString tid, String msgId,
      AuditEvent event) throws InsuffientPermissionException {
    long confirmWaitTime = cmpControl.getConfirmWaitTime();
    if (confirmWaitTime < 0) {
      confirmWaitTime *= -1;
    }
    confirmWaitTime *= 1000; // second to millisecond

    PKIBody respBody;

    int type = reqBody.getType();
    switch (type) {
      case PKIBody.TYPE_INIT_REQ:
        checkPermission(requestor, PermissionConstants.ENROLL_CERT);
        respBody = processIr(dfltCertprofileName, dfltKeyGenType, request, requestor, tid,
            reqHeader, CertReqMessages.getInstance(reqBody.getContent()), cmpControl, msgId, event);
        break;
      case PKIBody.TYPE_CERT_REQ:
        checkPermission(requestor, PermissionConstants.ENROLL_CERT);
        respBody = processCr(dfltCertprofileName, dfltKeyGenType, request, requestor, tid,
            reqHeader, CertReqMessages.getInstance(reqBody.getContent()), cmpControl, msgId, event);
        break;
      case PKIBody.TYPE_KEY_UPDATE_REQ:
        checkPermission(requestor, PermissionConstants.KEY_UPDATE);
        respBody = processKur(dfltCertprofileName, dfltKeyGenType, request, requestor, tid,
            reqHeader, CertReqMessages.getInstance(reqBody.getContent()), cmpControl, msgId, event);
        break;
      case PKIBody.TYPE_P10_CERT_REQ:
        checkPermission(requestor, PermissionConstants.ENROLL_CERT);
        respBody = processP10cr(dfltCertprofileName, request, requestor, tid, reqHeader,
            CertificationRequest.getInstance(reqBody.getContent()), cmpControl, msgId, event);
        break;
      case PKIBody.TYPE_CROSS_CERT_REQ:
        checkPermission(requestor, PermissionConstants.ENROLL_CROSS);
        respBody = processCcp(dfltCertprofileName, request, requestor, tid, reqHeader,
            CertReqMessages.getInstance(reqBody.getContent()), cmpControl, msgId, event);
        break;
      default:
        throw new RuntimeException("should not reach here");
    } // switch type

    InfoTypeAndValue tv = null;
    if (!cmpControl.isConfirmCert() && CmpUtil.isImplictConfirm(reqHeader)) {
      pendingCertPool.removeCertificates(tid.getOctets());
      tv = CmpUtil.getImplictConfirmGeneralInfo();
    } else {
      Date now = new Date();
      respHeader.setMessageTime(new ASN1GeneralizedTime(now));
      tv = new InfoTypeAndValue(CMPObjectIdentifiers.it_confirmWaitTime,
          new ASN1GeneralizedTime(new Date(System.currentTimeMillis() + confirmWaitTime)));
    }

    respHeader.setGeneralInfo(tv);
    return respBody;
  } // method cmpEnrollCert

  private PKIBody cmpUnRevokeRemoveCertificates(PKIMessage request, PKIHeaderBuilder respHeader,
      CmpControl cmpControl, PKIHeader reqHeader, PKIBody reqBody, CmpRequestorInfo requestor,
      String msgId, AuditEvent event) {
    Integer requiredPermission = null;
    boolean allRevdetailsOfSameType = true;

    RevReqContent rr = RevReqContent.getInstance(reqBody.getContent());
    RevDetails[] revContent = rr.toRevDetailsArray();

    int len = revContent.length;
    for (int i = 0; i < len; i++) {
      RevDetails revDetails = revContent[i];
      Extensions crlDetails = revDetails.getCrlEntryDetails();
      int reasonCode = CrlReason.UNSPECIFIED.getCode();
      if (crlDetails != null) {
        ASN1ObjectIdentifier extId = Extension.reasonCode;
        ASN1Encodable extValue = crlDetails.getExtensionParsedValue(extId);
        if (extValue != null) {
          reasonCode = ASN1Enumerated.getInstance(extValue).getValue().intValue();
        }
      }

      if (reasonCode == XiSecurityConstants.CMP_CRL_REASON_REMOVE) {
        if (requiredPermission == null) {
          event.addEventType(CaAuditConstants.TYPE_CMP_rr_remove);
          requiredPermission = PermissionConstants.REMOVE_CERT;
        } else if (requiredPermission != PermissionConstants.REMOVE_CERT) {
          allRevdetailsOfSameType = false;
          break;
        }
      } else if (reasonCode == CrlReason.REMOVE_FROM_CRL.getCode()) {
        if (requiredPermission == null) {
          event.addEventType(CaAuditConstants.TYPE_CMP_rr_unrevoke);
          requiredPermission = PermissionConstants.UNREVOKE_CERT;
        } else if (requiredPermission != PermissionConstants.UNREVOKE_CERT) {
          allRevdetailsOfSameType = false;
          break;
        }
      } else {
        if (requiredPermission == null) {
          event.addEventType(CaAuditConstants.TYPE_CMP_rr_revoke);
          requiredPermission = PermissionConstants.REVOKE_CERT;
        } else if (requiredPermission != PermissionConstants.REVOKE_CERT) {
          allRevdetailsOfSameType = false;
          break;
        }
      }
    } // end for

    if (!allRevdetailsOfSameType) {
      ErrorMsgContent emc = new ErrorMsgContent(
          new PKIStatusInfo(PKIStatus.rejection,
          new PKIFreeText("not all revDetails are of the same type"),
          new PKIFailureInfo(PKIFailureInfo.badRequest)));

      return new PKIBody(PKIBody.TYPE_ERROR, emc);
    }

    try {
      checkPermission(requestor, requiredPermission);
    } catch (InsuffientPermissionException ex) {
      event.setStatus(AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, "NOT_PERMITTED");
      return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.notAuthorized, null);
    }

    return unRevokeRemoveCertificates(request, rr, requiredPermission, cmpControl, msgId, event);
  } // method cmpRevokeOrUnrevokeOrRemoveCertificates

  private PKIBody cmpGeneralMsg(PKIHeaderBuilder respHeader, CmpControl cmpControl,
      PKIHeader reqHeader, PKIBody reqBody, CmpRequestorInfo requestor, ASN1OctetString tid,
      String msgId, AuditEvent event) throws InsuffientPermissionException {
    GenMsgContent genMsgBody = GenMsgContent.getInstance(reqBody.getContent());
    InfoTypeAndValue[] itvs = genMsgBody.toInfoTypeAndValueArray();

    InfoTypeAndValue itv = null;
    if (itvs != null && itvs.length > 0) {
      for (InfoTypeAndValue entry : itvs) {
        String itvType = entry.getInfoType().getId();
        if (KNOWN_GENMSG_IDS.contains(itvType)) {
          itv = entry;
          break;
        }
      }
    }

    if (itv == null) {
      String statusMessage = "PKIBody type " + PKIBody.TYPE_GEN_MSG
          + " is only supported with the sub-types " + KNOWN_GENMSG_IDS.toString();
      return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest, statusMessage);
    }

    InfoTypeAndValue itvResp = null;
    ASN1ObjectIdentifier infoType = itv.getInfoType();

    int failureInfo;
    try {
      X509Ca ca = getCa();
      if (CMPObjectIdentifiers.it_currentCRL.equals(infoType)) {
        event.addEventType(CaAuditConstants.TYPE_CMP_genm_current_crl);
        checkPermission(requestor, PermissionConstants.GET_CRL);
        CertificateList crl = ca.getBcCurrentCrl();

        if (itv.getInfoValue() == null) { // as defined in RFC 4210
          crl = ca.getBcCurrentCrl();
        } else {
          // xipki extension
          ASN1Integer crlNumber = ASN1Integer.getInstance(itv.getInfoValue());
          crl = ca.getBcCrl(crlNumber.getPositiveValue());
        }

        if (crl == null) {
          return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.systemFailure,
              "no CRL is available");
        }

        itvResp = new InfoTypeAndValue(infoType, crl);
      } else if (ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.equals(infoType)) {
        ASN1Encodable asn1 = itv.getInfoValue();
        ASN1Integer asn1Code = null;
        ASN1Encodable reqValue = null;

        try {
          ASN1Sequence seq = ASN1Sequence.getInstance(asn1);
          asn1Code = ASN1Integer.getInstance(seq.getObjectAt(0));
          if (seq.size() > 1) {
            reqValue = seq.getObjectAt(1);
          }
        } catch (IllegalArgumentException ex) {
          return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
              "invalid value of the InfoTypeAndValue for "
              + ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId());
        }

        ASN1Encodable respValue;

        int action = asn1Code.getPositiveValue().intValue();
        switch (action) {
          case XiSecurityConstants.CMP_ACTION_GEN_CRL:
            event.addEventType(CaAuditConstants.TYPE_CMP_genm_gen_crl);
            checkPermission(requestor, PermissionConstants.GEN_CRL);
            X509CRL tmpCrl = ca.generateCrlOnDemand(msgId);
            if (tmpCrl == null) {
              String statusMessage = "CRL generation is not activated";
              return buildErrorMsgPkiBody(PKIStatus.rejection,
                  PKIFailureInfo.systemFailure, statusMessage);
            } else {
              respValue = CertificateList.getInstance(tmpCrl.getEncoded());
            }
            break;
          case XiSecurityConstants.CMP_ACTION_GET_CRL_WITH_SN:
            event.addEventType(CaAuditConstants.TYPE_CMP_genm_crl4number);
            checkPermission(requestor, PermissionConstants.GET_CRL);

            ASN1Integer crlNumber = ASN1Integer.getInstance(reqValue);
            respValue = ca.getBcCrl(crlNumber.getPositiveValue());
            if (respValue == null) {
              String statusMessage = "no CRL is available";
              return buildErrorMsgPkiBody(PKIStatus.rejection,
                  PKIFailureInfo.systemFailure, statusMessage);
            }
            break;
          case XiSecurityConstants.CMP_ACTION_GET_CAINFO:
            event.addEventType(CaAuditConstants.TYPE_CMP_genm_cainfo);
            Set<Integer> acceptVersions = new HashSet<>();
            if (reqValue != null) {
              ASN1Sequence seq = DERSequence.getInstance(reqValue);
              int size = seq.size();
              for (int i = 0; i < size; i++) {
                ASN1Integer ai = ASN1Integer.getInstance(seq.getObjectAt(i));
                acceptVersions.add(ai.getPositiveValue().intValue());
              }
            }

            if (CollectionUtil.isEmpty(acceptVersions)) {
              acceptVersions.add(1);
            }

            String systemInfo = getSystemInfo(requestor, acceptVersions);
            respValue = new DERUTF8String(systemInfo);
            break;
          default:
            return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest,
                "unsupported XiPKI action code " + action);
        } // end switch (action)

        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(asn1Code);
        if (respValue != null) {
          vec.add(respValue);
        }
        itvResp = new InfoTypeAndValue(infoType, new DERSequence(vec));
      } else if (ObjectIdentifiers.id_xipki_cmp_cacerts.equals(infoType)) {
        event.addEventType(CaAuditConstants.TYPE_CMP_genm_cacerts);
        CMPCertificate caCert = ca.getCaInfo().getCertInCmpFormat();
        itvResp = new InfoTypeAndValue(infoType, new DERSequence(caCert));
      }

      GenRepContent genRepContent = new GenRepContent(itvResp);
      return new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);
    } catch (OperationException ex) {
      failureInfo = getPKiFailureInfo(ex);
      ErrorCode code = ex.getErrorCode();

      String errorMessage;
      switch (code) {
        case DATABASE_FAILURE:
        case SYSTEM_FAILURE:
          errorMessage = code.name();
          break;
        default:
          errorMessage = code.name() + ": " + ex.getErrorMessage();
          break;
      } // end switch code

      return buildErrorMsgPkiBody(PKIStatus.rejection, failureInfo, errorMessage);
    } catch (CRLException ex) {
      return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.systemFailure,
          "CRLException: " + ex.getMessage());
    }
  } // method cmpGeneralMsg

  public CertificateList getCrl(CmpRequestorInfo requestor, BigInteger crlNumber)
      throws OperationException {
    ParamUtil.requireNonNull("requestor", requestor);
    try {
      checkPermission(requestor, PermissionConstants.GET_CRL);
    } catch (InsuffientPermissionException ex) {
      throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
    }
    X509Ca ca = getCa();
    return (crlNumber == null) ? ca.getBcCurrentCrl() : ca.getBcCrl(crlNumber);
  }

  public X509CRL generateCrlOnDemand(CmpRequestorInfo requestor, RequestType reqType, String msgId)
      throws OperationException {
    ParamUtil.requireNonNull("requestor", requestor);
    try {
      checkPermission(requestor, PermissionConstants.GEN_CRL);
    } catch (InsuffientPermissionException ex) {
      throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
    }

    return getCa().generateCrlOnDemand(msgId);
  }

  public void revokeCert(CmpRequestorInfo requestor, BigInteger serialNumber, CrlReason reason,
      Date invalidityDate, RequestType reqType, String msgId) throws OperationException {
    ParamUtil.requireNonNull("requestor", requestor);

    int permission;
    if (reason == CrlReason.REMOVE_FROM_CRL) {
      permission = PermissionConstants.UNREVOKE_CERT;
    } else {
      permission = PermissionConstants.REVOKE_CERT;
    }
    try {
      checkPermission(requestor, permission);
    } catch (InsuffientPermissionException ex) {
      throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
    }

    X509Ca ca = getCa();
    Object returnedObj;
    if (PermissionConstants.UNREVOKE_CERT == permission) {
      // unrevoke
      returnedObj = ca.unrevokeCert(serialNumber, msgId);
    } else {
      returnedObj = ca.revokeCert(serialNumber, reason, invalidityDate, msgId);
    } // end if (permission)

    if (returnedObj == null) {
      throw new OperationException(ErrorCode.UNKNOWN_CERT, "cert not exists");
    }
  }

  public void removeCert(CmpRequestorInfo requestor, BigInteger serialNumber, RequestType reqType,
      String msgId) throws OperationException {
    ParamUtil.requireNonNull("requestor", requestor);
    try {
      checkPermission(requestor, PermissionConstants.REMOVE_CERT);
    } catch (InsuffientPermissionException ex) {
      throw new OperationException(ErrorCode.NOT_PERMITTED, ex.getMessage());
    }

    CertWithDbId returnedObj = getCa().removeCert(serialNumber, msgId);
    if (returnedObj == null) {
      throw new OperationException(ErrorCode.UNKNOWN_CERT, "cert not exists");
    }
  }

  private static PKIBody buildErrorMsgPkiBody(PKIStatus pkiStatus, int failureInfo,
      String statusMessage) {
    PKIFreeText pkiStatusMsg = (statusMessage == null) ? null : new PKIFreeText(statusMessage);
    ErrorMsgContent emc = new ErrorMsgContent(
        new PKIStatusInfo(pkiStatus, pkiStatusMsg, new PKIFailureInfo(failureInfo)));
    return new PKIBody(PKIBody.TYPE_ERROR, emc);
  }

  private CertResponse buildErrorCertResponse(ASN1Integer certReqId, int pkiFailureInfo,
      String pkiStatusText) {
    return new CertResponse(certReqId, generateRejectionStatus(pkiFailureInfo, pkiStatusText));
  }

}
