// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
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
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.crmf.DhSigStatic;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
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
import org.xipki.ca.gateway.CaNameSigners;
import org.xipki.ca.gateway.PopControl;
import org.xipki.ca.gateway.api.Requestor;
import org.xipki.ca.gateway.api.RequestorAuthenticator;
import org.xipki.ca.sdk.CaAuditConstants;
import org.xipki.ca.sdk.ErrorResponse;
import org.xipki.ca.sdk.SdkClient;
import org.xipki.ca.sdk.SdkErrorResponseException;
import org.xipki.cmp.CmpUtil;
import org.xipki.cmp.ProtectionResult;
import org.xipki.cmp.ProtectionVerificationResult;
import org.xipki.pki.ErrorCode;
import org.xipki.pki.OperationException;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InsufficientPermissionException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Base CMP responder.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public abstract class BaseCmpResponder {

  public static final String HTTP_HEADER_certprofile = "certprofile";

  public static final String HTTP_HEADER_groupenroll = "groupenroll";

  public static final String TYPE_ccr = "ccr";

  public static final String TYPE_certConf = "cert_conf";

  public static final String TYPE_ir = "ir";

  public static final String TYPE_cr = "cr";

  public static final String TYPE_error = "error";

  public static final String TYPE_genm_cacerts = "genm_cacerts";

  public static final String TYPE_genm_current_crl = "genm_current_crl";

  public static final String TYPE_kur = "kur";

  public static final String TYPE_p10cr = "p10cr";

  public static final String TYPE_pkiconf = "pkiconf";

  public static final String TYPE_rr_revoke = "rr_revoke";

  public static final String TYPE_rr_unrevoke = "rr_unrevoke";

  private static final Logger LOG = LoggerFactory.getLogger(BaseCmpResponder.class);

  private static final int PVNO_CMP2000 = 2;

  private static final AlgorithmIdentifier prf_hmacWithSHA256 = SignAlgo.HMAC_SHA256.getAlgorithmIdentifier();

  private static final Map<ErrorCode, Integer> errorCodeToPkiFailureMap = new HashMap<>(20);

  protected final SecurityFactory securityFactory;

  private final SecureRandom random = new SecureRandom();

  protected final SdkClient sdk;

  protected final CmpControl cmpControl;

  protected final PopControl popControl;

  private final RequestorAuthenticator authenticator;

  private final CaNameSigners signers;

  private final KeyGenerator aesKeyGen;

  static {
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

  protected BaseCmpResponder(
      CmpControl cmpControl, SdkClient sdk, SecurityFactory securityFactory,
      CaNameSigners signers, RequestorAuthenticator authenticator, PopControl popControl)
      throws NoSuchAlgorithmException {
    this.sdk = sdk;
    this.securityFactory = securityFactory;
    this.authenticator = authenticator;
    this.cmpControl = cmpControl;
    this.popControl = popControl;
    this.signers = signers;
    this.aesKeyGen = KeyGenerator.getInstance("AES");
  }

  protected abstract PKIBody cmpEnrollCert(
      String caName, String dfltCertprofileName, boolean groupEnroll,
      PKIMessage request, PKIHeaderBuilder respHeader, PKIHeader reqHeader, PKIBody reqBody,
      Requestor requestor, ASN1OctetString tid, AuditEvent event)
      throws InsufficientPermissionException, SdkErrorResponseException;

  protected abstract PKIBody cmpUnRevokeCertificates(
      String caName, PKIMessage request, PKIHeaderBuilder respHeader, PKIHeader reqHeader,
      PKIBody reqBody, Requestor requestor, AuditEvent event)
      throws SdkErrorResponseException;

  protected abstract PKIBody confirmCertificates(
      String caName, ASN1OctetString transactionId, CertConfirmContent certConf)
      throws SdkErrorResponseException;

  protected abstract PKIBody revokePendingCertificates(String caName, ASN1OctetString transactionId)
      throws SdkErrorResponseException;

  private Requestor.CertRequestor getCertRequestor(
      X500Name requestorSender, byte[] senderKID, CMPCertificate[] extraCerts) {
    if (extraCerts == null) {
      return null;
    }

    for (CMPCertificate cc : extraCerts) {
      Certificate c = cc.getX509v3PKCert();
      if (c == null) {
        continue;
      }

      boolean match = requestorSender == null || requestorSender.equals(c.getSubject());
      if (!match) {
        continue;
      }

      X509Cert xc = new X509Cert(c);
      match = senderKID == null || Arrays.equals(xc.getSubjectKeyId(), senderKID);
      if (match) {
        return getCertRequestor(xc);
      }
    }
    return null;
  }

  private Requestor.SimplePasswordRequestor getPasswordRequestor(byte[] senderKID) {
    return authenticator.getSimplePasswordRequestorByKeyId(senderKID);
  }

  private Requestor.CertRequestor getCertRequestor(X509Cert senderCert) {
    return authenticator.getCertRequestor(senderCert);
  }

  protected static X500Name getX500Name(GeneralName name) {
    if (name.getTagNo() != GeneralName.directoryName) {
      return null;
    }

    return (X500Name) name.getName();
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
   * @param parameters
   *          Additional parameters.
   * @param event
   *          Audit event. Must not be {@code null}.
   * @return the response
   */
  private PKIMessage processPkiMessage0(
      String caName, PKIMessage request, Requestor requestor, ASN1OctetString tid,
      GeneralPKIMessage message, Map<String, String> parameters, AuditEvent event) {
    event.addEventData(CaAuditConstants.NAME_requestor, requestor == null ? "null" : requestor.getName());

    PKIHeader reqHeader = message.getHeader();

    PKIHeaderBuilder respHeader = new PKIHeaderBuilder(
        reqHeader.getPvno().getValue().intValue(), reqHeader.getRecipient(), reqHeader.getSender());
    respHeader.setTransactionID(tid);
    ASN1OctetString senderNonce = reqHeader.getSenderNonce();
    if (senderNonce != null) {
      respHeader.setRecipNonce(senderNonce);
    }

    PKIBody respBody;

    PKIBody reqBody = message.getBody();
    final int type = reqBody.getType();

    try {
      if (type == PKIBody.TYPE_INIT_REQ || type == PKIBody.TYPE_CERT_REQ
          || type == PKIBody.TYPE_KEY_UPDATE_REQ || type == PKIBody.TYPE_P10_CERT_REQ
          || type == PKIBody.TYPE_CROSS_CERT_REQ) {
        String eventType;

        if (PKIBody.TYPE_CERT_REQ == type) {
          eventType = TYPE_cr;
        } else if (PKIBody.TYPE_INIT_REQ == type) {
          eventType = TYPE_ir;
        } else if (PKIBody.TYPE_KEY_UPDATE_REQ == type) {
          eventType = TYPE_kur;
        } else if (PKIBody.TYPE_P10_CERT_REQ == type) {
          eventType = TYPE_p10cr;
        } else {// if (PKIBody.TYPE_CROSS_CERT_REQ == type) {
          eventType = TYPE_ccr;
        }

        event.addEventType(eventType);

        String dfltCertprofileName = null;
        boolean groupEnroll = false;
        if (parameters != null) {
          dfltCertprofileName = parameters.get(HTTP_HEADER_certprofile);
          String str = parameters.get(HTTP_HEADER_groupenroll);
          groupEnroll = !StringUtil.isBlank(str) && Boolean.parseBoolean(str);
        }

        respBody = cmpEnrollCert(caName, dfltCertprofileName, groupEnroll, request, respHeader,
            reqHeader, reqBody, requestor, tid, event);
      } else if (type == PKIBody.TYPE_CERT_CONFIRM) {
        event.addEventType(TYPE_certConf);
        CertConfirmContent certConf = (CertConfirmContent) reqBody.getContent();
        respBody = confirmCertificates(caName, tid, certConf);
      } else if (type == PKIBody.TYPE_REVOCATION_REQ) {
        respBody = cmpUnRevokeCertificates(caName, request, respHeader, reqHeader, reqBody, requestor, event);
      } else if (type == PKIBody.TYPE_CONFIRM) {
        event.addEventType(TYPE_pkiconf);
        respBody = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
      } else if (type == PKIBody.TYPE_GEN_MSG) {
        respBody = cmpGeneralMsg(caName, reqBody, event);
      } else if (type == PKIBody.TYPE_ERROR) {
        event.addEventType(TYPE_error);
        respBody = revokePendingCertificates(caName, tid);
      } else {
        event.addEventType("PKIBody." + type);
        respBody = buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest, "unsupported type " + type);
      }
    } catch (InsufficientPermissionException ex) {
      ErrorMsgContent emc = new ErrorMsgContent( new PKIStatusInfo(
          PKIStatus.rejection, new PKIFreeText(ex.getMessage()), new PKIFailureInfo(PKIFailureInfo.notAuthorized)));

      respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
    } catch (SdkErrorResponseException ex) {
      LogUtil.error(LOG, ex);
      ErrorResponse errResp = ex.getErrorResponse();
      respBody = new PKIBody(PKIBody.TYPE_ERROR,
          new ErrorMsgContent(buildPKIStatusInfo(errResp.getCode(), errResp.getMessage())));
    }

    if (respBody.getType() == PKIBody.TYPE_ERROR) {
      ErrorMsgContent errorMsgContent = (ErrorMsgContent) respBody.getContent();

      org.xipki.cmp.PkiStatusInfo pkiStatus = new org.xipki.cmp.PkiStatusInfo(errorMsgContent.getPKIStatusInfo());

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

  public PKIMessage processPkiMessage(
      String caName, PKIMessage pkiMessage, X509Cert tlsClientCert, Map<String, String> parameters, AuditEvent event) {
    Args.notNull(event, "event");
    GeneralPKIMessage message = new GeneralPKIMessage(Args.notNull(pkiMessage, "pkiMessage"));

    PKIHeader reqHeader = message.getHeader();
    ASN1OctetString tid = reqHeader.getTransactionID();
    if (tid == null) {
      tid = new DEROctetString(randomTransactionId());
    }
    String tidStr = Base64.encodeToString(tid.getOctets());
    event.addEventData(CaAuditConstants.NAME_tid, tidStr);

    final GeneralName respSender = reqHeader.getRecipient();

    int reqPvno = reqHeader.getPvno().getValue().intValue();
    if (reqPvno < PVNO_CMP2000) {
      event.update(AuditLevel.INFO, AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, "unsupported version " + reqPvno);
      return buildErrorPkiMessage(tid, reqHeader, PKIFailureInfo.unsupportedVersion, null, respSender);
    }

    Integer failureCode = null;
    String statusText = null;

    Instant messageTime = null;
    if (reqHeader.getMessageTime() != null) {
      try {
        messageTime = reqHeader.getMessageTime().getDate().toInstant();
      } catch (ParseException ex) {
        LogUtil.error(LOG, ex, "tid=" + tidStr + ": could not parse messageTime");
      }
    }

    ConcurrentContentSigner signer = signers.getSigner(caName);

    GeneralName recipient = reqHeader.getRecipient();
    X500Name x500Name = getX500Name(recipient);
    if (x500Name != null) {
      RDN[] rdns = x500Name.getRDNs();
      // consider the empty DN
      if ((rdns != null && rdns.length > 0) // Not an empty DN
          && !signer.getCertificate().getSubject().equals(x500Name)) {
        LOG.warn("tid={}: I am not the intended recipient, but '{}'", tid, reqHeader.getRecipient());
        failureCode = PKIFailureInfo.badRequest;
        statusText = "I am not the intended recipient";
      }
    }

    if (messageTime == null) {
      if (cmpControl.isMessageTimeRequired()) {
        failureCode = PKIFailureInfo.missingTimeStamp;
        statusText = "missing time-stamp";
      }
    } else {
      long messageTimeBiasSeconds = cmpControl.getMessageTimeBias().getSeconds();

      long msgTime = messageTime.getEpochSecond();
      long currentTime = Instant.now().getEpochSecond();
      long bias = msgTime - currentTime;
      if (bias > messageTimeBiasSeconds) {
        failureCode = PKIFailureInfo.badTime;
        statusText = "message time is in the future";
      } else if (bias * -1 > messageTimeBiasSeconds) {
        failureCode = PKIFailureInfo.badTime;
        statusText = "message too old";
      }
    }

    if (failureCode != null) {
      event.update(AuditLevel.INFO, AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, statusText);
      return buildErrorPkiMessage(tid, reqHeader, failureCode, statusText, respSender);
    }

    boolean isProtected = message.hasProtection();

    Requestor requestor;
    String errorStatus;

    if (isProtected) {
      try {
        ProtectionVerificationResult verificationResult = verifyProtection(tidStr, message);
        ProtectionResult pr = verificationResult.getProtectionResult();
        switch (pr) {
          case SIGNATURE_VALID:
          case MAC_VALID:
            errorStatus = null;
            break;
          case SIGNATURE_INVALID:
            errorStatus = "request is protected by signature but invalid";
            break;
          case MAC_INVALID:
            errorStatus = "request is protected by MAC but invalid";
            break;
          case SENDER_NOT_AUTHORIZED:
            errorStatus = "request is protected but the requestor is not authorized";
            break;
          case SIGNATURE_ALGO_FORBIDDEN:
            errorStatus = "request is protected by signature but the algorithm is forbidden";
            break;
          case MAC_ALGO_FORBIDDEN:
            errorStatus = "request is protected by MAC but the algorithm is forbidden";
            break;
          default:
            throw new IllegalStateException("should not reach here, unknown ProtectionResult " + pr);
        }

        requestor = (Requestor) verificationResult.getRequestor();
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "tid=" + tidStr + ": could not verify the signature");
        errorStatus = "request has invalid signature based protection";
        requestor = null;
      }
    } else if (tlsClientCert != null) {
      X500Name x500ReqSender = getX500Name(reqHeader.getSender());
      requestor = (x500ReqSender == null) ? null : getCertRequestor(tlsClientCert);

      if (requestor != null) {
        errorStatus = null;
      } else {
        LOG.warn("tid={}: not authorized requestor (TLS client '{}')", tid, tlsClientCert.getSubjectText());
        errorStatus = "requestor (TLS client certificate) is not authorized";
      }
    } else {
      requestor = null;
      final int type = message.getBody().getType();
      if (type != PKIBody.TYPE_GEN_MSG) {
        LOG.warn("tid={}: message is not protected", tid);
        errorStatus = "message is not protected";
      } else {
        errorStatus = null;
      }
    }

    if (errorStatus != null) {
      event.update(AuditLevel.INFO, AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, errorStatus);
      return buildErrorPkiMessage(tid, reqHeader, PKIFailureInfo.badMessageCheck, errorStatus, respSender);
    }

    PKIMessage resp = processPkiMessage0(caName, pkiMessage, requestor, tid, message, parameters, event);

    if (isProtected) {
      resp = addProtection(signer, resp, event, requestor);
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

  private ProtectionVerificationResult verifyProtection(String tid, GeneralPKIMessage pkiMessage)
      throws CMPException, InvalidKeyException {
    ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

    PKIHeader header = protectedMsg.getHeader();
    byte[] senderKID = header.getSenderKID() == null ? null : header.getSenderKID().getOctets();
    AlgorithmIdentifier protectionAlg = header.getProtectionAlg();

    if (protectedMsg.hasPasswordBasedMacProtection()) {
      PBMParameter parameter = PBMParameter.getInstance(pkiMessage.getHeader().getProtectionAlg().getParameters());
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

      if (macAlg == null) {
        LOG.error("macAlg unknown");
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

      PKMACBuilder pkMacBuilder = new PKMACBuilder(new JcePKMACValuesCalculator());
      Requestor.SimplePasswordRequestor requestor = getPasswordRequestor(senderKID);

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
        LOG.warn("SIG_ALGO_FORBIDDEN: {}", pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
        return new ProtectionVerificationResult(null, ProtectionResult.SIGNATURE_ALGO_FORBIDDEN);
      }

      X500Name x500Sender = getX500Name(header.getSender());
      Requestor.CertRequestor requestor = (x500Sender == null) ? null
          : getCertRequestor(x500Sender, senderKID, pkiMessage.toASN1Structure().getExtraCerts());
      if (requestor == null) {
        LOG.warn("tid={}: not authorized requestor '{}'", tid, header.getSender());
        return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      ContentVerifierProvider verifierProvider = securityFactory.getContentVerifierProvider(requestor.getCert());
      if (verifierProvider == null) {
        LOG.warn("tid={}: not authorized requestor '{}'", tid, header.getSender());
        return new ProtectionVerificationResult(requestor, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      boolean signatureValid = protectedMsg.verify(verifierProvider);
      return new ProtectionVerificationResult(requestor,
          signatureValid ? ProtectionResult.SIGNATURE_VALID : ProtectionResult.SIGNATURE_INVALID);
    }
  } // method verifyProtection

  private PKIMessage addProtection(
      ConcurrentContentSigner signer, PKIMessage pkiMessage, AuditEvent event, Requestor requestor) {
    GeneralName respSender = pkiMessage.getHeader().getSender();
    try {
      if (requestor instanceof Requestor.CertRequestor) {
        return CmpUtil.addProtection(pkiMessage, signer, respSender, cmpControl.isSendResponderCert());
      } else {
        Requestor.SimplePasswordRequestor requestor0 = (Requestor.SimplePasswordRequestor) requestor;
        PBMParameter parameter = new PBMParameter(
            randomSalt(),
            cmpControl.getResponsePbmOwf().getAlgorithmIdentifier(),
            cmpControl.getResponsePbmIterationCount(),
            cmpControl.getResponsePbmMac().getAlgorithmIdentifier());
        return CmpUtil.addProtection(pkiMessage, requestor0.getPassword(),
                  parameter, respSender, requestor0.getKeyId());
      }
    } catch (Exception ex) {
      LogUtil.error(LOG, ex, "could not add protection to the PKI message");
      PKIStatusInfo status = generateRejectionStatus(
          PKIFailureInfo.systemFailure, "could not sign the PKIMessage");

      event.update(AuditLevel.ERROR, AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, "could not sign the PKIMessage");
      return new PKIMessage(pkiMessage.getHeader(), new PKIBody(PKIBody.TYPE_ERROR, new ErrorMsgContent(status)));
    }
  } // method addProtection

  private PKIMessage buildErrorPkiMessage(
      ASN1OctetString tid, PKIHeader requestHeader, int failureCode, String statusText, GeneralName respSender) {
    GeneralName respRecipient = requestHeader.getSender();

    PKIHeaderBuilder respHeader = new PKIHeaderBuilder(
        requestHeader.getPvno().getValue().intValue(), respSender, respRecipient);
    respHeader.setMessageTime(new ASN1GeneralizedTime(Date.from(Instant.now())));
    if (tid != null) {
      respHeader.setTransactionID(tid);
    }

    ASN1OctetString senderNonce = requestHeader.getSenderNonce();
    if (senderNonce != null) {
      respHeader.setRecipNonce(senderNonce);
    }

    PKIStatusInfo status = generateRejectionStatus(failureCode, statusText);

    return new PKIMessage(respHeader.build(), new PKIBody(PKIBody.TYPE_ERROR, new ErrorMsgContent(status)));
  } // method buildErrorPkiMessage

  protected static PKIStatusInfo generateRejectionStatus(Integer info, String errorMessage) {
    return generateRejectionStatus(PKIStatus.rejection, info, errorMessage);
  }

  protected static PKIStatusInfo generateRejectionStatus(PKIStatus status, Integer info, String errorMessage) {
    PKIFreeText statusMessage = (errorMessage == null) ? null : new PKIFreeText(errorMessage);
    PKIFailureInfo failureInfo = (info == null) ? null : new PKIFailureInfo(info);
    return new PKIStatusInfo(status, statusMessage, failureInfo);
  }

  protected static int getPKiFailureInfo(OperationException ex) {
    Integer failureInfo = errorCodeToPkiFailureMap.get(ex.getErrorCode());
    return failureInfo == null ? PKIFailureInfo.systemFailure : failureInfo;
  }

  protected void checkPermission(Requestor requestor, Requestor.Permission requiredPermission)
      throws InsufficientPermissionException {
    if (!requestor.isPermitted(requiredPermission)) {
      throw new InsufficientPermissionException(requiredPermission + "is not permitted");
    }
  }

  protected static PKIBody buildErrorMsgPkiBody(PKIStatus pkiStatus, int failureInfo, String statusMessage) {
    PKIFreeText pkiStatusMsg = (statusMessage == null) ? null : new PKIFreeText(statusMessage);
    ErrorMsgContent emc = new ErrorMsgContent(
        new PKIStatusInfo(pkiStatus, pkiStatusMsg, new PKIFailureInfo(failureInfo)));
    return new PKIBody(PKIBody.TYPE_ERROR, emc);
  }

  protected static CertRepMessage buildErrCertResp(ASN1Integer certReqId, int pkiFailureInfo, String pkiStatusText) {
    return new CertRepMessage(null,
        new CertResponse[]{new CertResponse(certReqId, generateRejectionStatus(pkiFailureInfo, pkiStatusText))});
  }

  protected static void addErrCertResp(
      Map<Integer, CertResponse> resps, int index, ASN1Integer certReqId, int pkiFailureInfo, String pkiStatusText) {
    resps.put(index, new CertResponse(certReqId, generateRejectionStatus(pkiFailureInfo, pkiStatusText)));
  }

  protected boolean verifyPop(CertificateRequestMessage certRequest, SubjectPublicKeyInfo spki) {
    int popType = certRequest.getProofOfPossessionType();
    if (popType == CertificateRequestMessage.popRaVerified) {
      return false;
    }

    if (popType != CertificateRequestMessage.popSigningKey) {
      LOG.error("unsupported POP type: " + popType);
      return false;
    }

    // check the POP signature algorithm
    ProofOfPossession pop = certRequest.toASN1Structure().getPop();
    POPOSigningKey popSign = POPOSigningKey.getInstance(pop.getObject());
    SignAlgo popAlg;
    try {
      popAlg = SignAlgo.getInstance(popSign.getAlgorithmIdentifier());
    } catch (NoSuchAlgorithmException ex) {
      LogUtil.error(LOG, ex, "Cannot parse POP signature algorithm");
      return false;
    }

    if (popAlg == null) {
      LOG.error("POP signature algorithm unknown");
      return false;
    }

    AlgorithmValidator algoValidator = popControl.getPopAlgoValidator();
    if (!algoValidator.isAlgorithmPermitted(popAlg)) {
      LOG.error("POP signature algorithm {} not permitted", popAlg.getJceName());
      return false;
    }

    try {
      PublicKey publicKey = securityFactory.generatePublicKey(spki);

      DHSigStaticKeyCertPair kaKeyAndCert = null;
      if (SignAlgo.DHPOP_X25519 == popAlg || SignAlgo.DHPOP_X448 == popAlg) {
        DhSigStatic dhSigStatic = DhSigStatic.getInstance(popSign.getSignature().getBytes());
        IssuerAndSerialNumber isn = dhSigStatic.getIssuerAndSerial();

        ASN1ObjectIdentifier keyAlgOid = spki.getAlgorithm().getAlgorithm();
        kaKeyAndCert = popControl.getDhKeyCertPair(isn.getName(),
            isn.getSerialNumber().getValue(), EdECConstants.getName(keyAlgOid));

        if (kaKeyAndCert == null) {
          return false;
        }
      }

      ContentVerifierProvider cvp = securityFactory.getContentVerifierProvider(publicKey, kaKeyAndCert);
      return certRequest.isValidSigningKeyPOP(cvp);
    } catch (InvalidKeyException | IllegalStateException | CRMFException ex) {
      LogUtil.error(LOG, ex);
    }
    return false;
  } // method verifyPop

  protected CertResponse postProcessCertInfo(
      ASN1Integer certReqId, Requestor requestor, byte[] cert, byte[] privateKeyinfo) {
    PKIStatusInfo statusInfo = new PKIStatusInfo(PKIStatus.granted);
    CertOrEncCert cec = new CertOrEncCert(new CMPCertificate(org.bouncycastle.asn1.x509.Certificate.getInstance(cert)));
    if (privateKeyinfo == null) {
      // no private key will be returned.
      return new CertResponse(certReqId, statusInfo, new CertifiedKeyPair(cec), null);
    }

    final int aesGcmTagByteLen = 16;
    final int aesGcmNonceLen = 12;

    PrivateKeyInfo privKey = PrivateKeyInfo.getInstance(privateKeyinfo);
    AlgorithmIdentifier intendedAlg = privKey.getPrivateKeyAlgorithm();
    EncryptedValue encKey;

    try {
      if (requestor instanceof Requestor.CertRequestor) {
        Requestor.CertRequestor certRequestor = (Requestor.CertRequestor) requestor;
        // use private key of the requestor to encrypt the private key
        PublicKey reqPub = certRequestor.getCert().getPublicKey();
        CrmfKeyWrapper wrapper;
        if (reqPub instanceof RSAPublicKey) {
          wrapper = new CrmfKeyWrapper.RSAOAEPAsymmetricKeyWrapper(reqPub);
        } else if (reqPub instanceof ECPublicKey) {
          wrapper = new CrmfKeyWrapper.ECIESAsymmetricKeyWrapper(reqPub);
        } else {
          String msg = "Requestors's private key can not be used for encryption";
          LOG.error(msg);
          return new CertResponse(certReqId, new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(msg)));
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

        Cipher dataCipher = Cipher.getInstance(symmAlgOid.getId());

        try {
          dataCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(symmKeyBytes, "AES"),
              new GCMParameterSpec(aesGcmTagByteLen << 3, nonce));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
          throw new IllegalStateException(ex);
        }
        byte[] encValue = dataCipher.doFinal(privKey.getEncoded());

        GCMParameters params = new GCMParameters(nonce, aesGcmTagByteLen);
        AlgorithmIdentifier symmAlg = new AlgorithmIdentifier(symmAlgOid, params);

        encKey = new EncryptedValue(intendedAlg, symmAlg,
            new DERBitString(encSymmKey), keyAlg, null, new DERBitString(encValue));
      } else {
        Requestor.SimplePasswordRequestor passwordRequestor = (Requestor.SimplePasswordRequestor) requestor;

        final ASN1ObjectIdentifier encAlgOid = NISTObjectIdentifiers.id_aes128_GCM;
        final int keysizeBits = 128; // one of 128, 192 and 256. Must match the encAlgOid
        final int iterCount = 10240; // >= 1000
        final int nonceLen = 12; // fixed value
        final int tagByteLen = 16; // fixed value

        byte[] nonce = randomBytes(nonceLen);

        // use password of the requestor to encrypt the private key
        byte[] pbkdfSalt = randomBytes(keysizeBits / 8);

        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(PKCSObjectIdentifiers.id_PBKDF2.getId());

        SecretKey key = keyFact.generateSecret(new PBKDF2KeySpec(passwordRequestor.getPassword(), pbkdfSalt,
            iterCount, keysizeBits, prf_hmacWithSHA256));
        key = new SecretKeySpec(key.getEncoded(), "AES");

        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(tagByteLen * 8, nonce);

        Cipher dataCipher = Cipher.getInstance(encAlgOid.getId());

        dataCipher.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec);
        byte[] encValue = dataCipher.doFinal(privKey.getEncoded());

        AlgorithmIdentifier symmAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2,
            new PBES2Parameters(
                new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2,
                    new PBKDF2Params(pbkdfSalt, iterCount, keysizeBits / 8, prf_hmacWithSHA256)),
                new EncryptionScheme(encAlgOid, new GCMParameters(nonce, tagByteLen))));

        encKey = new EncryptedValue(intendedAlg, symmAlg, null, null, null, new DERBitString(encValue));
      }
    } catch (Throwable th) {
      String msg = "error while encrypting the private key";
      LogUtil.error(LOG, th, msg);
      return new CertResponse(certReqId, new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(msg)));
    }

    return new CertResponse(certReqId, statusInfo, new CertifiedKeyPair(cec, encKey, null), null);
  }

  protected PKIBody cmpGeneralMsg(String caName, PKIBody reqBody, AuditEvent event)
      throws SdkErrorResponseException {
    GenMsgContent genMsgBody = GenMsgContent.getInstance(reqBody.getContent());
    InfoTypeAndValue[] itvs = genMsgBody.toInfoTypeAndValueArray();

    InfoTypeAndValue itv = null;
    if (itvs != null) {
      for (InfoTypeAndValue entry : itvs) {
        String itvType = entry.getInfoType().getId();
        if (CMPObjectIdentifiers.id_it_caCerts.getId().equals(itvType)
            || CMPObjectIdentifiers.it_currentCRL.getId().equals(itvType)) {
          itv = entry;
          break;
        }
      }
    }

    if (itv == null) {
      String statusMessage = "PKIBody type " + PKIBody.TYPE_GEN_MSG + " with given sub-type is not supported";
      return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest, statusMessage);
    }

    InfoTypeAndValue itvResp;
    ASN1ObjectIdentifier infoType = itv.getInfoType();

    if (CMPObjectIdentifiers.it_currentCRL.equals(infoType)) {
      event.addEventType(TYPE_genm_current_crl);
      byte[] encodedCrl = sdk.currentCrl(caName);
      if (encodedCrl == null) {
        return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.systemFailure, "no CRL is available");
      }

      CertificateList crl = CertificateList.getInstance(encodedCrl);
      itvResp = new InfoTypeAndValue(infoType, crl);
    } else { // if (CMPObjectIdentifiers.id_it_caCerts.equals(infoType)) {
      event.addEventType(TYPE_genm_cacerts);
      byte[][] certchain = sdk.cacerts(caName);
      if (certchain == null || certchain.length == 0) {
        return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.systemFailure, "no certchain is available");
      }

      ASN1EncodableVector vec = new ASN1EncodableVector();
      for (byte[] cert : certchain) {
        vec.add(new CMPCertificate(Certificate.getInstance(cert)));
      }
      itvResp = new InfoTypeAndValue(infoType, new DERSequence(vec));
    }

    GenRepContent genRepContent = new GenRepContent(itvResp);
    return new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);
  } // method cmpGeneralMsg

  static PKIStatusInfo buildPKIStatusInfo(int errorCode, String message) {
    ErrorCode code;
    try {
      code = ErrorCode.ofCode(errorCode);
    } catch (Exception ex) {
      LOG.warn("unknown error code {}, map it to {}", errorCode, ErrorCode.SYSTEM_FAILURE);
      code = ErrorCode.SYSTEM_FAILURE;
    }
    return buildPKIStatusInfo(code, message);
  }

  static PKIStatusInfo buildPKIStatusInfo(ErrorCode errorCode, String message) {
    PKIFreeText freeText = message == null ? null : new PKIFreeText(message);

    int failureInfo;
    switch (errorCode) {
      case ALREADY_ISSUED:
        failureInfo = PKIFailureInfo.duplicateCertReq;
        break;
      case BAD_CERT_TEMPLATE:
      case INVALID_EXTENSION:
        failureInfo = PKIFailureInfo.badCertTemplate;
        break;
      case BAD_REQUEST:
      case CERT_UNREVOKED:
      case UNKNOWN_CERT:
      case UNKNOWN_CERT_PROFILE:
        failureInfo = PKIFailureInfo.badRequest;
        break;
      case BAD_POP:
        failureInfo = PKIFailureInfo.badPOP;
        break;
      case CERT_REVOKED:
        failureInfo = PKIFailureInfo.certRevoked;
        break;
      case NOT_PERMITTED:
      case UNAUTHORIZED:
        failureInfo = PKIFailureInfo.notAuthorized;
        break;
      case SYSTEM_UNAVAILABLE:
        failureInfo = PKIFailureInfo.systemUnavail;
        break;
      case CRL_FAILURE:
      case DATABASE_FAILURE:
      case SYSTEM_FAILURE:
      case PATH_NOT_FOUND:
      default:
        failureInfo = PKIFailureInfo.systemFailure;
        break;
    }

    return new PKIStatusInfo(PKIStatus.rejection, freeText, new PKIFailureInfo(failureInfo));
  }

}
