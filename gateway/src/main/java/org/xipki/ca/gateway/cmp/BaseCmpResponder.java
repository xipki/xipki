// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.pkix.asn1.cmp.*;
import org.xipki.pkix.asn1.cms.EnvelopedData;
import org.xipki.codec.asn1.crypto.GCMParameters;
import org.xipki.pkix.asn1.cms.IssuerAndSerialNumber;
import org.xipki.pkix.asn1.crmf.DhSigStatic;
import org.xipki.pkix.asn1.crmf.EncryptedKey;
import org.xipki.pkix.asn1.crmf.EncryptedValue;
import org.xipki.pkix.asn1.crmf.POPOSigningKey;
import org.xipki.pkix.asn1.crmf.ProofOfPossession;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PBES2Parameters;
import org.xipki.codec.asn1.crypto.PBKDF2Params;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.RSAESOAEPParams;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.CmpOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.codec.asn1.oid.XipkiOIDs;
import org.xipki.pkix.asn1.util.ContentVerifierProvider;
import org.xipki.pkix.asn1.x500.RDN;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.CertificateList;
import org.xipki.pkix.asn1.x509.GeneralName;
import org.xipki.ca.gateway.CaNameSigners;
import org.xipki.ca.gateway.PopControl;
import org.xipki.ca.sdk.CaAuditConstants;
import org.xipki.ca.sdk.ErrorResponse;
import org.xipki.ca.sdk.SdkClient;
import org.xipki.ca.sdk.SdkErrorResponseException;
import org.xipki.codec.util.Args;
import org.xipki.codec.Base64;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.pkix.cmp.CmpException;
import org.xipki.pkix.cmp.ProtectedPKIMessage;
import org.xipki.pkix.cms.CmsAlgorithm;
import org.xipki.pkix.cms.CmsEnvelopedData;
import org.xipki.pkix.cmp.CertificateRequestMessage;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.SecurityFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.auth.Requestor;
import org.xipki.pkix.auth.RequestorAuthenticator;
import org.xipki.pkix.cmp.CmpUtil;
import org.xipki.pkix.cmp.PkiStatusInfo;
import org.xipki.pkix.cmp.ProtectionResult;
import org.xipki.pkix.cmp.ProtectionVerificationResult;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.pkix.exception.ErrorCode;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.KemHmacSignature;
import org.xipki.crypto.core.EcCurveEnum;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.crypto.core.SecretKeyWithAlias;
import org.xipki.pkix.verify.AlgorithmValidator;
import org.xipki.util.audit.AuditEvent;
import org.xipki.util.audit.AuditLevel;
import org.xipki.util.audit.AuditStatus;
import org.xipki.codec.exception.InsufficientPermissionException;
import org.xipki.pkix.util.misc.LogUtil;
import org.xipki.pkix.util.misc.StringUtil;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Base CMP Responder.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class BaseCmpResponder {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private static final int cmp2000 = 2;

  private static final int cmp2021 = 3;

  public static final String HTTP_HEADER_certprofile = "certprofile";

  public static final String HTTP_HEADER_groupenroll = "groupenroll";

  public static final String TYPE_ccr = "ccr";

  public static final String TYPE_certConf = "cert_conf";

  public static final String TYPE_ir = "ir";

  public static final String TYPE_cr = "cr";

  public static final String TYPE_error = "error";

  public static final String TYPE_genm_cacerts = "genm_cacerts";

  public static final String TYPE_genm_current_crl = "genm_current_crl";

  public static final String TYPE_genm_kem_keycap = "genm_kem_keycap";

  public static final String TYPE_kur = "kur";

  public static final String TYPE_p10cr = "p10cr";

  public static final String TYPE_pkiconf = "pkiconf";

  public static final String TYPE_rr_revoke = "rr_revoke";

  public static final String TYPE_rr_unrevoke = "rr_unrevoke";

  private static final Logger LOG = LoggerFactory.getLogger(BaseCmpResponder.class);

  private static final int PVNO_CMP2000 = 2;

  private static final AlgorithmIdentifier prf_hmacWithSHA256 =
      SignAlgo.HMAC_SHA256.algorithmIdentifier();

  private static final Map<ErrorCode, PKIFailureInfo> errorCodeToPkiFailureMap =
      new HashMap<>(20);

  protected final SecurityFactory securityFactory;

  private final SecureRandom random = new SecureRandom();

  protected final SdkClient sdk;

  protected final CmpControl cmpControl;

  protected final PopControl popControl;

  private final RequestorAuthenticator authenticator;

  private final CaNameSigners signers;

  private final KeyGenerator aesKeyGen;

  static {
    errorCodeToPkiFailureMap.put(ErrorCode.ALREADY_ISSUED,     PKIFailureInfo.badRequest);
    errorCodeToPkiFailureMap.put(ErrorCode.BAD_CERT_TEMPLATE,  PKIFailureInfo.badCertTemplate);
    errorCodeToPkiFailureMap.put(ErrorCode.BAD_REQUEST,        PKIFailureInfo.badRequest);
    errorCodeToPkiFailureMap.put(ErrorCode.CERT_REVOKED,       PKIFailureInfo.certRevoked);
    errorCodeToPkiFailureMap.put(ErrorCode.CERT_UNREVOKED,     PKIFailureInfo.notAuthorized);
    errorCodeToPkiFailureMap.put(ErrorCode.BAD_POP,            PKIFailureInfo.badPOP);
    errorCodeToPkiFailureMap.put(ErrorCode.NOT_PERMITTED,      PKIFailureInfo.notAuthorized);
    errorCodeToPkiFailureMap.put(ErrorCode.INVALID_EXTENSION,  PKIFailureInfo.badRequest);
    errorCodeToPkiFailureMap.put(ErrorCode.SYSTEM_UNAVAILABLE, PKIFailureInfo.systemUnavail);
    errorCodeToPkiFailureMap.put(ErrorCode.UNKNOWN_CERT,       PKIFailureInfo.badCertId);
    errorCodeToPkiFailureMap.put(ErrorCode.UNKNOWN_CERT_PROFILE, PKIFailureInfo.badCertTemplate);
  }

  protected BaseCmpResponder(
      CmpControl cmpControl, SdkClient sdk, SecurityFactory securityFactory,
      CaNameSigners signers, RequestorAuthenticator authenticator, PopControl popControl)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    this.sdk = sdk;
    this.securityFactory = securityFactory;
    this.authenticator = authenticator;
    this.cmpControl = cmpControl;
    this.popControl = popControl;
    this.signers = signers;
    this.aesKeyGen = cryptoApi.newKeyGenerator("AES");
  }

  protected abstract PKIBody cmpEnrollCert(
      CmpVersion cmpVersion, String caName, String dfltCertprofileName, boolean groupEnroll,
      PKIMessage request, PKIHeader respHeader, PKIHeader reqHeader, PKIBody reqBody,
      Requestor requestor, Asn1OctetString tid, AuditEvent event)
      throws InsufficientPermissionException, SdkErrorResponseException;

  protected abstract PKIBody cmpUnRevokeCertificates(
      String caName, PKIMessage request, PKIHeader respHeader,
      PKIHeader reqHeader, PKIBody reqBody, Requestor requestor, AuditEvent event)
      throws SdkErrorResponseException;

  protected abstract PKIBody confirmCertificates(
      String caName, Asn1OctetString transactionId, CertConfirmContent certConf)
      throws SdkErrorResponseException;

  protected abstract PKIBody revokePendingCertificates(
      String caName, Asn1OctetString transactionId) throws SdkErrorResponseException;

  private Requestor.CertRequestor getCertRequestor(
      X500Name requestorSender, byte[] senderKID, CMPCertificate.Seq1 extraCerts) {
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

      X509Cert xc;
      try {
        xc = new X509Cert(c);
      } catch (CodecException e) {
        return null;
      }

      match = senderKID == null || Arrays.equals(xc.subjectKeyId(), senderKID);
      if (match) {
        return getCertRequestor(xc);
      }
    }
    return null;
  }

  private Requestor.SimplePasswordRequestor getPasswordRequestor(byte[] senderKID) {
    return authenticator.getSimplePasswordRequestorByKeyId(Requestor.Protocol.CMP, senderKID);
  }

  private Requestor.CertRequestor getCertRequestor(X509Cert senderCert) {
    return authenticator.getCertRequestor(Requestor.Protocol.CMP, senderCert);
  }

  protected static X500Name getX500Name(GeneralName name) {
    if (name.getTagNo() != GeneralName.tag_directoryName) {
      return null;
    }

    return name.getDirectoryName();
  } // method getX500Sender

  /**
   * Processes the request and returns the response.
   * @param request
   *        Original request. Will only be used for the storage.
   *        Could be{@code null}.
   * @param requestor
   *        Requestor. Must not be {@code null}.
   * @param tid
   *        Transaction id. Must not be {@code null}.
   * @param message
   *        PKI message. Must not be {@code null}.
   * @param parameters
   *        Additional parameters.
   * @param event
   *        Audit event. Must not be {@code null}.
   * @return the response
   */
  private PKIMessage processPkiMessage0(
      String caName, PKIMessage request, Requestor requestor, Asn1OctetString tid,
      PKIMessage message, Map<String, String> parameters, AuditEvent event) {
    event.addEventData(CaAuditConstants.NAME_requestor,
        requestor == null ? "null" : requestor.name());

    PKIHeader reqHeader = message.getHeader();
    CmpVersion cmpVersion = new CmpVersion(reqHeader);

    PKIHeader respHeader = new PKIHeader(
        reqHeader.pvno(), reqHeader.getRecipient(), reqHeader.getSender());
    respHeader.setTransactionID(tid);
    Asn1OctetString senderNonce = reqHeader.getSenderNonce();
    if (senderNonce != null) {
      respHeader.setRecipNonce(senderNonce);
    }

    PKIBody respBody;

    PKIBody reqBody = message.getBody();
    final int type = reqBody.getTagNo();

    try {
      if (type == PKIBody.tag_ir     || type == PKIBody.tag_cr
          || type == PKIBody.tag_kur || type == PKIBody.tag_p10cr
          || type == PKIBody.tag_ccr) {
        String eventType =
              (PKIBody.tag_cr == type)    ? TYPE_cr
            : (PKIBody.tag_ir == type)    ? TYPE_ir
            : (PKIBody.tag_kur == type)   ? TYPE_kur
            : (PKIBody.tag_p10cr == type) ? TYPE_p10cr
            : TYPE_ccr; // for (PKIBody.TYPE_CROSS_CERT_REQ == type)

        event.addEventType(eventType);

        String dfltCertprofileName = null;
        boolean groupEnroll = false;
        if (parameters != null) {
          dfltCertprofileName = parameters.get(HTTP_HEADER_certprofile);
          String str = parameters.get(HTTP_HEADER_groupenroll);
          groupEnroll = !StringUtil.isBlank(str) && Boolean.parseBoolean(str);
        }

        respBody = cmpEnrollCert(cmpVersion, caName, dfltCertprofileName,
            groupEnroll, request, respHeader, reqHeader, reqBody, requestor, tid, event);
      } else if (type == PKIBody.tag_certConf) {
        event.addEventType(TYPE_certConf);
        CertConfirmContent certConf = reqBody.getCertConf();
        respBody = confirmCertificates(caName, tid, certConf);
      } else if (type == PKIBody.tag_rr) {
        respBody = cmpUnRevokeCertificates(caName, request, respHeader,
                    reqHeader, reqBody, requestor, event);
      } else if (type == PKIBody.tag_pkiconf) {
        event.addEventType(TYPE_pkiconf);
        respBody = PKIBody.ofPkiconf();
      } else if (type == PKIBody.tag_genm) {
        respBody = cmpGeneralMsg(caName, reqBody, event);
      } else if (type == PKIBody.tag_error) {
        event.addEventType(TYPE_error);
        respBody = revokePendingCertificates(caName, tid);
      } else {
        event.addEventType("PKIBody." + type);
        respBody = buildErrorMsgPkiBody(PKIStatus.rejection,
            PKIFailureInfo.badRequest, "unsupported type " + type);
      }
    } catch (InsufficientPermissionException ex) {
      ErrorMsgContent emc = new ErrorMsgContent( new PKIStatusInfo(
          PKIStatus.rejection, new PKIFreeText(ex.getMessage()), PKIFailureInfo.notAuthorized));

      respBody = PKIBody.ofError(emc);
    } catch (SdkErrorResponseException ex) {
      LogUtil.error(LOG, ex);
      ErrorResponse errResp = ex.errorResponse();
      respBody = PKIBody.ofError(
          new ErrorMsgContent(buildPKIStatusInfo(errResp.code(), errResp.message())));
    }

    if (respBody.getTagNo() == PKIBody.tag_error) {
      ErrorMsgContent errorMsgContent = reqBody.getError();

      PkiStatusInfo pkiStatus = new PkiStatusInfo(errorMsgContent.getPkiStatusInfo());

      event.setStatus(AuditStatus.FAILED);
      String statusString = pkiStatus.statusMessage();
      if (statusString != null) {
        event.addEventData(CaAuditConstants.NAME_message, statusString);
      }
    } else if (event.status() == null) {
      event.setStatus(AuditStatus.SUCCESSFUL);
    }

    if (cmpVersion.respVersion != respHeader.pvno()) {
      // change the cmp version in response
      respHeader.setPvno(cmpVersion.respVersion);
    }

    return new PKIMessage(respHeader, respBody);
  } // method processPKIMessage0

  public PKIMessage processPkiMessage(
      String caName, PKIMessage pkiMessage, X509Cert tlsClientCert,
      Map<String, String> parameters, AuditEvent event) {
    Args.notNull(event, "event");
    PKIMessage message = Args.notNull(pkiMessage, "pkiMessage");

    PKIHeader reqHeader = message.getHeader();
    Asn1OctetString tid = reqHeader.getTransactionID();
    if (tid == null) {
      tid = new Asn1OctetString(randomTransactionId());
    }
    String tidStr = Base64.encodeToString(tid.getOctets());
    event.addEventData(CaAuditConstants.NAME_tid, tidStr);

    final GeneralName respSender = reqHeader.getRecipient();

    int reqPvno = reqHeader.pvno();
    if (reqPvno < PVNO_CMP2000) {
      event.update(AuditLevel.INFO, AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, "unsupported version " + reqPvno);
      return buildErrorPkiMessage(tid, reqHeader,
          PKIFailureInfo.unsupportedVersion, null, respSender);
    }

    PKIFailureInfo failureCode = null;
    String statusText = null;

    Instant messageTime = null;
    if (reqHeader.getMessageTime() != null) {
      messageTime = reqHeader.messageTime();
    }

    ConcurrentSigner signer = signers.getSigner(caName);

    GeneralName recipient = reqHeader.getRecipient();
    X500Name x500Name = getX500Name(recipient);
    if (x500Name != null) {
      List<RDN> rdns = x500Name.getRDNs();
      // consider the empty DN
      if ((rdns != null && !rdns.isEmpty()) // Not an empty DN
          && !signer.x509Cert().subject().equals(x500Name)) {
        LOG.warn("tid={}: I am not the intended recipient, but '{}'",
            tid, reqHeader.getRecipient());
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
      long messageTimeBiasSeconds = cmpControl.messageTimeBias().getSeconds();

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
        ProtectionResult pr = verificationResult.protectionResult();
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
            throw new IllegalStateException("unknown ProtectionResult " + pr);
        }

        requestor = (Requestor) verificationResult.requestor();
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
        LOG.warn("tid={}: not authorized requestor (TLS client '{}')",
            tid, tlsClientCert.subjectText());
        errorStatus = "requestor (TLS client certificate) is not authorized";
      }
    } else {
      requestor = null;
      final int type = message.getBody().getTagNo();
      if (type != PKIBody.tag_genm) {
        LOG.warn("tid={}: message is not protected", tid);
        errorStatus = "message is not protected";
      } else {
        errorStatus = null;
      }
    }

    if (errorStatus != null) {
      event.update(AuditLevel.INFO, AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, errorStatus);
      return buildErrorPkiMessage(tid, reqHeader,
          PKIFailureInfo.badMessageCheck, errorStatus, respSender);
    }

    PKIMessage resp = processPkiMessage0(caName, pkiMessage,
        requestor, tid, message, parameters, event);

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

  private ProtectionVerificationResult verifyProtection(String tid, PKIMessage pkiMessage)
      throws CmpException, InvalidKeyException {
    ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

    PKIHeader header = protectedMsg.getHeader();
    byte[] senderKID = header.senderKID();
    AlgorithmIdentifier protectionAlg = header.getProtectionAlg();

    if (protectedMsg.hasPasswordBasedMacProtection()) {
      if (senderKID == null) {
        LOG.warn("tid={}: senderKID is null", tid);
        return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      PBMParameter parameter;
      try {
        parameter = PBMParameter.fromAsn1(
          pkiMessage.getHeader().getProtectionAlg().getParameters().asSequence());
      } catch (CodecException ex) {
        LOG.warn("malformed protection algorithm", ex);
        return new ProtectionVerificationResult(null, ProtectionResult.SIGNATURE_INVALID);
      }

      HashAlgo owfAlg;
      try {
        owfAlg = HashAlgo.getInstance(parameter.getOwf());
      } catch (NoSuchAlgorithmException ex) {
        LogUtil.warn(LOG, ex);
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }
      if (!cmpControl.isRequestPbmOwfPermitted(owfAlg)) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.owf: {})", owfAlg.jceName());
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
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.mac: {})", macAlg.jceName());
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      int iterationCount = parameter.iterationCount();
      if (iterationCount < ProtectedPKIMessage.MIN_PBM_ITERATION_COUNT) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.iterationCount: {} < {})", iterationCount,
            ProtectedPKIMessage.MIN_PBM_ITERATION_COUNT);
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      if (iterationCount > cmpControl.requestPbmMaxIterationCount()) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.iterationCount: {} > {})", iterationCount,
            cmpControl.requestPbmMaxIterationCount());
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      Requestor.SimplePasswordRequestor requestor = getPasswordRequestor(senderKID);

      if (requestor == null) {
        LOG.warn("tid={}: not authorized requestor with senderKID '{}'",
            tid, Hex.encode(senderKID));
        return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
      }

      boolean macValid = protectedMsg.verify(requestor.password(),
          cmpControl.requestPbmMaxIterationCount());
      return new ProtectionVerificationResult(requestor,
          macValid ? ProtectionResult.MAC_VALID : ProtectionResult.MAC_INVALID);
    } else {
      if (!cmpControl.sigAlgoValidator().isAlgorithmPermitted(protectionAlg)) {
        LOG.warn("SIG_ALGO_FORBIDDEN: {}",
            pkiMessage.getHeader().getProtectionAlg().getAlgorithm().getId());
        return new ProtectionVerificationResult(null, ProtectionResult.SIGNATURE_ALGO_FORBIDDEN);
      }

      X500Name x500Sender = getX500Name(header.getSender());
      Requestor.CertRequestor requestor = (x500Sender == null) ? null
          : getCertRequestor(x500Sender, senderKID, pkiMessage.getExtraCerts());

      ContentVerifierProvider verifierProvider = requestor == null ? null
          : securityFactory.getContentVerifierProvider(requestor.cert());
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
      ConcurrentSigner signer, PKIMessage pkiMessage, AuditEvent event, Requestor requestor) {
    GeneralName respSender = pkiMessage.getHeader().getSender();
    try {
      if (requestor instanceof Requestor.CertRequestor) {
        return CmpUtil.addProtection(pkiMessage, signer, respSender,
                cmpControl.isSendResponderCert());
      } else {
        Requestor.SimplePasswordRequestor requestor0 =
            (Requestor.SimplePasswordRequestor) requestor;

        PBMParameter parameter = new PBMParameter(randomSalt(),
            cmpControl.responsePbmOwf().algorithmIdentifier(),
            cmpControl.responsePbmIterationCount(),
            cmpControl.responsePbmMac().algorithmIdentifier());
        return CmpUtil.addProtection(pkiMessage, requestor0.password(),
                  parameter, respSender, requestor0.keyId());
      }
    } catch (Exception ex) {
      LogUtil.error(LOG, ex, "could not add protection to the PKI message");
      PKIStatusInfo status = generateRejectionStatus(
          PKIFailureInfo.systemFailure, "could not sign the PKIMessage");

      event.update(AuditLevel.ERROR, AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, "could not sign the PKIMessage");
      return new PKIMessage(pkiMessage.getHeader(),
          PKIBody.ofError(new ErrorMsgContent(status)));
    }
  } // method addProtection

  private PKIMessage buildErrorPkiMessage(
      Asn1OctetString tid, PKIHeader requestHeader, PKIFailureInfo failureCode,
      String statusText, GeneralName respSender) {
    GeneralName respRecipient = requestHeader.getSender();

    PKIHeader respHeader = new PKIHeader(requestHeader.pvno(), respSender, respRecipient);
    respHeader.setMessageTime(new Asn1GeneralizedTime(Instant.now()));

    if (tid != null) {
      respHeader.setTransactionID(tid);
    }

    Asn1OctetString senderNonce = requestHeader.getSenderNonce();
    if (senderNonce != null) {
      respHeader.setRecipNonce(senderNonce);
    }

    PKIStatusInfo status = generateRejectionStatus(failureCode, statusText);

    return new PKIMessage(respHeader, PKIBody.ofError(new ErrorMsgContent(status)));
  } // method buildErrorPkiMessage

  protected static PKIStatusInfo generateRejectionStatus(PKIFailureInfo info, String errorMessage) {
    return generateRejectionStatus(PKIStatus.rejection, info, errorMessage);
  }

  protected static PKIStatusInfo generateRejectionStatus(
      PKIStatus status, PKIFailureInfo failureInfo, String errorMessage) {
    PKIFreeText statusMessage = (errorMessage == null) ? null : new PKIFreeText(errorMessage);
    return new PKIStatusInfo(status, statusMessage, failureInfo);
  }

  protected void checkPermission(Requestor requestor, Requestor.Permission requiredPermission)
      throws InsufficientPermissionException {
    if (!requestor.isPermitted(requiredPermission)) {
      throw new InsufficientPermissionException(requiredPermission + "is not permitted");
    }
  }

  protected static PKIBody buildErrorMsgPkiBody(
      PKIStatus pkiStatus, PKIFailureInfo failureInfo, String statusMessage) {
    PKIFreeText pkiStatusMsg = (statusMessage == null)
        ? null : new PKIFreeText(statusMessage);
    ErrorMsgContent emc = new ErrorMsgContent(new PKIStatusInfo(
        pkiStatus, pkiStatusMsg, failureInfo));
    return PKIBody.ofError(emc);
  }

  protected static CertRepMessage buildErrCertResp(
      Asn1Integer certReqId, PKIFailureInfo pkiFailureInfo, String pkiStatusText) {
    return new CertRepMessage(null,
        new CertResponse.Seq0(
            new CertResponse(certReqId, generateRejectionStatus(pkiFailureInfo, pkiStatusText))));
  }

  protected static void addErrCertResp(
      Map<Integer, CertResponse> resps, int index, Asn1Integer certReqId,
      PKIFailureInfo pkiFailureInfo, String pkiStatusText) {
    resps.put(index, new CertResponse(certReqId,
        generateRejectionStatus(pkiFailureInfo, pkiStatusText)));
  }

  protected boolean verifyPop(CertificateRequestMessage certRequest, SubjectPublicKeyInfo spki) {
    int popType = certRequest.getProofOfPossessionType();
    if (popType == CertificateRequestMessage.tag_popRaVerified) {
      return false;
    }

    if (popType != CertificateRequestMessage.tag_popSigningKey) {
      LOG.error("unsupported POP type: {}", popType);
      return false;
    }

    // check the POP signature algorithm
    ProofOfPossession pop = certRequest.toASN1Structure().getPop();
    POPOSigningKey popSign = pop.getSignature();
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

    AlgorithmValidator algoValidator = popControl.popAlgoValidator();
    if (!algoValidator.isAlgorithmPermitted(popAlg)) {
      LOG.error("POP signature algorithm {} not permitted", popAlg.jceName());
      return false;
    }

    try {
      PublicKey publicKey = securityFactory.generatePublicKey(spki);

      DHSigStaticKeyCertPair kaKeyAndCert = null;
      if (SignAlgo.DHPOP_X25519 == popAlg || SignAlgo.DHPOP_X448 == popAlg) {
        DhSigStatic dhSigStatic = DhSigStatic.fromEncoded(popSign.signature());
        IssuerAndSerialNumber isn = dhSigStatic.getIssuerAndSerial();

        Asn1Oid keyAlgOid = spki.getAlgorithm().getAlgorithm();
        EcCurveEnum curve = EcCurveEnum.ofOid(keyAlgOid);
        assert curve != null;

        kaKeyAndCert = popControl.getDhKeyCertPair(isn.getName(),
            isn.serialNumber(), curve.mainAlias());

        if (kaKeyAndCert == null) {
          LOG.warn("found no DH key and cert matching issuer={} and serial number={}",
              isn.getName(), isn.serialNumber());
          return false;
        }
      }

      SecretKey ownerMasterKey = null;
      if (SignAlgo.KEM_HMAC_SHA256 == popAlg) {
        KemHmacSignature kemHmacSig = KemHmacSignature.decode(popSign.signature());
        SecretKeyWithAlias km = popControl.kemMasterKey(kemHmacSig.id());
        if (km != null) {
          ownerMasterKey = km.secretKey();
        }
      }

      ContentVerifierProvider cvp = securityFactory.getContentVerifierProvider(
          publicKey, kaKeyAndCert, ownerMasterKey);
      return certRequest.isValidSigningKeyPOP(cvp);
    } catch (CodecException | InvalidKeyException | IllegalStateException | CmpException ex) {
      LogUtil.error(LOG, ex);
    }
    return false;
  } // method verifyPop

  protected CertResponse postProcessCertInfo(
      CmpVersion cmpVersion, Asn1Integer certReqId, Requestor requestor,
      byte[] cert, byte[] privateKeyinfo, EphemeralKeyPair ephemeralKeyPair) {
    Certificate asn1Cert;
    try {
      asn1Cert = Certificate.fromEncoded(cert);
    } catch (CodecException e) {
      String m = "Certificate that will be sent to client is malformed";
      LOG.error(m, e);
      return new CertResponse(certReqId,
          new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(m)));
    }

    CertOrEncCert cec = CertOrEncCert.ofCertificate(CMPCertificate.ofX509v3PKCert(asn1Cert));
    if (privateKeyinfo == null) {
      // no private key will be returned.
      return new CertResponse(certReqId, new PKIStatusInfo(PKIStatus.accepted),
          new CertifiedKeyPair(cec), null);
    }

    int maxRespVersion = Math.min(cmpVersion.reqVersion, cmpVersion.respVersion);
    if (maxRespVersion >= cmp2021) {
      cmpVersion.respVersion = cmp2021;
      return postProcessCertInfoCmp2021(certReqId, requestor, cec, privateKeyinfo,
          ephemeralKeyPair);
    } else {
      cmpVersion.respVersion = Math.min(cmp2000, maxRespVersion);
      return postProcessCertInfoCmp2000(certReqId, requestor, cec, privateKeyinfo);
    }
  }

  private CertResponse postProcessCertInfoCmp2000(
      Asn1Integer certReqId, Requestor requestor, CertOrEncCert cec, byte[] privateKeyinfo) {
    PKIStatusInfo statusInfo = new PKIStatusInfo(PKIStatus.accepted);

    final int aesGcmTagByteLen = 16;
    final int aesGcmNonceLen = 12;

    PrivateKeyInfo privKey;
    try {
      privKey = PrivateKeyInfo.fromEncoded(privateKeyinfo);
    } catch (CodecException e) {
      String m = "Private key that will be sent to client is malformed";
      LOG.error(m, e);
      return new CertResponse(certReqId,
          new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(m)));
    }

    AlgorithmIdentifier intendedAlg = privKey.getPrivateKeyAlgorithm();
    EncryptedValue encKey;

    try {
      if (requestor instanceof Requestor.CertRequestor) {
        Requestor.CertRequestor certRequestor = (Requestor.CertRequestor) requestor;

        // use private key of the requestor to encrypt the private key
        PublicKey reqPub = certRequestor.cert().publicKey();
        CrmfKeyWrapper wrapper;
        if (reqPub instanceof RSAPublicKey) {
          wrapper = new CrmfKeyWrapper.RSAOAEPAsymmetricKeyWrapper(reqPub);
        } else if (reqPub instanceof ECPublicKey) {
          wrapper = new CrmfKeyWrapper.ECIESAsymmetricKeyWrapper((ECPublicKey) reqPub, random);
        } else {
          String m = "Requestors's private key can not be used for encryption";
          LOG.error(m);
          return new CertResponse(certReqId,
              new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(m)));
        }

        byte[] symmKeyBytes;
        synchronized (aesKeyGen) {
          aesKeyGen.init(128);
          symmKeyBytes = aesKeyGen.generateKey().getEncoded();
        }

        // encrypt the symmKey
        byte[] encSymmKey = wrapper.generateWrappedKey(symmKeyBytes);
        // algorithmIdentifier after the encryption process.
        AlgorithmIdentifier keyAlg = wrapper.getAlgorithmIdentifier();

        // encrypt the data
        Asn1Oid symmAlgOid = AlgorithmOIDs.id_aes128_GCM;
        byte[] nonce = randomBytes(aesGcmNonceLen);

        Cipher dataCipher = cryptoApi.newCipher(symmAlgOid.getId());

        try {
          dataCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(symmKeyBytes, "AES"),
              new GCMParameterSpec(aesGcmTagByteLen << 3, nonce));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
          LOG.error("error initializing dataCipher", ex);
          return new CertResponse(certReqId,
              new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText("intern system failure")));
        }
        byte[] encValue = dataCipher.doFinal(privKey.getEncoded());

        GCMParameters params = new GCMParameters(nonce, aesGcmTagByteLen);
        AlgorithmIdentifier symmAlg = AlgorithmIdentifier.build(symmAlgOid, params);

        encKey = new EncryptedValue(intendedAlg, symmAlg,
            (encSymmKey == null ? null : new Asn1BitString(encSymmKey)), keyAlg, null,
            new Asn1BitString(encValue));
      } else {
        Requestor.SimplePasswordRequestor passwordRequestor =
            (Requestor.SimplePasswordRequestor) requestor;
        final Asn1Oid encAlgOid = AlgorithmOIDs.id_aes128_GCM;
        // one of 128, 192 and 256. Must match the encAlgOid
        final int keysizeBits = 128;
        final int iterCount   = 10240; // >= 1000
        final int nonceLen    = 12; // fixed value
        final int tagByteLen  = 16; // fixed value

        byte[] nonce = randomBytes(nonceLen);

        // use password of the requestor to encrypt the private key
        byte[] pbkdfSalt = randomBytes(keysizeBits / 8);

        SecretKey key = new SecretKeySpec(cryptoApi.pbkdf2(prf_hmacWithSHA256,
            passwordRequestor.password(), pbkdfSalt, iterCount, keysizeBits / 8), "AES");

        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(tagByteLen * 8, nonce);

        Cipher dataCipher = cryptoApi.newCipher(encAlgOid.getId());
        dataCipher.init(Cipher.ENCRYPT_MODE, key, gcmParamSpec);
        byte[] encValue = dataCipher.doFinal(privKey.getEncoded());

        PBES2Parameters algParams = new PBES2Parameters(
            AlgorithmIdentifier.build(AlgorithmOIDs.id_PBKDF2,
                new PBKDF2Params(pbkdfSalt, iterCount, keysizeBits / 8, prf_hmacWithSHA256)),
            AlgorithmIdentifier.build(encAlgOid, new GCMParameters(nonce, tagByteLen)));

        AlgorithmIdentifier symmAlg = AlgorithmIdentifier.build(AlgorithmOIDs.id_PBES2, algParams);

        encKey =  new EncryptedValue(intendedAlg, symmAlg, null, null, null,
                    new Asn1BitString(encValue));
      }
    } catch (Throwable th) {
      String msg = "error while encrypting the private key";
      LogUtil.error(LOG, th, msg);
      return new CertResponse(certReqId,
          new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(msg)));
    }

    return new CertResponse(certReqId, statusInfo,
        new CertifiedKeyPair(cec, encKey, null), null);
  }

  private CertResponse postProcessCertInfoCmp2021(
      Asn1Integer certReqId, Requestor requestor, CertOrEncCert cec,
      byte[] privateKeyinfo, EphemeralKeyPair ephemeralKeyPair) {
    try {
      CmsEnvelopedData.Builder builder = new CmsEnvelopedData.Builder().setSecureRandom(random);
      if (requestor instanceof Requestor.CertRequestor) {
        Requestor.CertRequestor certRequestor = (Requestor.CertRequestor) requestor;
        X509Cert  recipientX509Cert = certRequestor.cert();
        PublicKey publicKey = recipientX509Cert.publicKey();
        if (publicKey instanceof RSAPublicKey) {
          // Use RSA/OAEP instead RSA/PKCS1
          AlgorithmIdentifier hashAlgId = HashAlgo.SHA256.algorithmIdentifier();
          AlgorithmIdentifier mgfAlgId =
              AlgorithmIdentifier.build(PkcsOIDs.id_mgf1, hashAlgId);
          AlgorithmIdentifier oaepAlgId = AlgorithmIdentifier.build(AlgorithmOIDs.id_RSAES_OAEP,
              new RSAESOAEPParams(hashAlgId, mgfAlgId, RSAESOAEPParams.DEFAULT_P_SOURCE_ALGORITHM));
          builder.addKeyTransRecipient(recipientX509Cert.getCert(), oaepAlgId);
        } else {
          // We use ECDHE with AES Key Wrap (standard for EC-based CMS)
          KeySpec keySpec = KeySpec.ofPublicKey(recipientX509Cert.subjectPublicKeyInfo());
          if (ephemeralKeyPair.keyPair == null) {
            ephemeralKeyPair.keyPair = KeyUtil.generateKeyPair(keySpec, random);
          }
          builder.addKeyAgreeRecipient(recipientX509Cert.getCert(),
              CmsAlgorithm.ECDH_SHA256KDF, // Key Agreement Algorithm
              CmsAlgorithm.AES256_WRAP, // Algorithm to wrap the content key
              ephemeralKeyPair.keyPair);
        }
      } else {
        Requestor.SimplePasswordRequestor passwordRequestor =
            (Requestor.SimplePasswordRequestor) requestor;

        // AES-256-CBC is used to wrap the content key (RFC 3211)
        builder.addPasswordRecipient(passwordRequestor.password(), CmsAlgorithm.AES256_CBC,
            prf_hmacWithSHA256, randomBytes(16), 10000);
      }

      // The content (private key) is encrypted with AES-256 GCM
      CmsEnvelopedData envelopedData = builder.build(CmsAlgorithm.AES256_GCM, privateKeyinfo);
      EnvelopedData envData = envelopedData.getEnvelopedData();

      EncryptedKey encryptedKey = EncryptedKey.ofEnvelopedData(envData);
      CertifiedKeyPair certifiedKeyPair =
           new CertifiedKeyPair(cec, encryptedKey, null);
      return new CertResponse(certReqId, new PKIStatusInfo(PKIStatus.accepted),
              certifiedKeyPair, null);
    } catch (Throwable th) {
      String msg = "error while encrypting the private key";
      LogUtil.error(LOG, th, msg);
      return new CertResponse(certReqId,
          new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(msg)));
    }
  }

  protected PKIBody cmpGeneralMsg(String caName, PKIBody reqBody, AuditEvent event)
      throws SdkErrorResponseException {
    GenMsgContent genMsgBody = reqBody.getGenm();

    InfoTypeAndValue itv = null;
    if (genMsgBody != null) {
      for (InfoTypeAndValue entry : genMsgBody) {
        String itvType = entry.getInfoType().getId();
        if (CmpOIDs.id_it_caCerts.getId().equals(itvType)
            || CmpOIDs.it_currentCRL.getId().equals(itvType)
            || XipkiOIDs.id_xipki_cmp_kem_encapkey.getId().equals(itvType)) {
          itv = entry;
          break;
        }
      }
    }

    if (itv == null) {
      String statusMessage = "PKIBody type " + PKIBody.tag_genm
          + " with given sub-type is not supported";
      return buildErrorMsgPkiBody(PKIStatus.rejection, PKIFailureInfo.badRequest, statusMessage);
    }

    InfoTypeAndValue itvResp;
    Asn1Oid infoType = itv.getInfoType();

    if (CmpOIDs.it_currentCRL.equals(infoType)) {
      event.addEventType(TYPE_genm_current_crl);
      byte[] encodedCrl = sdk.currentCrl(caName);
      if (encodedCrl == null) {
        return buildErrorMsgPkiBody(PKIStatus.rejection,
            PKIFailureInfo.systemFailure, "no CRL is available");
      }

      CertificateList crl;
      try {
        crl = CertificateList.fromEncoded(encodedCrl);
        itvResp = InfoTypeAndValue.build(infoType, crl);
      } catch (CodecException e) {
        return buildErrorMsgPkiBody(PKIStatus.rejection,
            PKIFailureInfo.systemFailure, "malformed CRL is available");
      }
    } else if (CmpOIDs.id_it_caCerts.equals(infoType)) {
      event.addEventType(TYPE_genm_cacerts);
      byte[][] certchain = sdk.cacerts(caName);
      if (certchain == null || certchain.length == 0) {
        return buildErrorMsgPkiBody(PKIStatus.rejection,
            PKIFailureInfo.systemFailure, "no certchain is available");
      }

      try {
        List<CMPCertificate> vec = new ArrayList<>(certchain.length);
        for (byte[] cert : certchain) {
          vec.add(CMPCertificate.ofX509v3PKCert(Certificate.fromEncoded(cert)));
        }

        itvResp = InfoTypeAndValue.build(infoType, new CMPCertificate.Seq1(vec));
      } catch (CodecException ex) {
        LOG.warn("malformed certificate", ex);
        return buildErrorMsgPkiBody(PKIStatus.rejection,
            PKIFailureInfo.systemFailure, "CodecException: " + ex.getMessage());
      }
    } else { // if (OIDs.Xipki.id_xipki_cmp_kem_encapkey.equals(infoType)) {
      event.addEventType(TYPE_genm_kem_keycap);
      SecretKeyWithAlias masterKey = popControl.defaultKemMasterKey();
      if (masterKey == null) {
        return buildErrorMsgPkiBody(PKIStatus.rejection,
            PKIFailureInfo.systemFailure, "no master key is available");
      }

      byte[] bytes = ((Asn1OctetString) itv.getInfoValue()).getOctets();

      KemEncapKey encapKey;
      try {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.fromEncoded(bytes);

        encapKey = KemUtil.generateKemEncapKey(spki, masterKey, random);
      } catch (XiSecurityException | CodecException e) {
        return buildErrorMsgPkiBody(PKIStatus.rejection,
            PKIFailureInfo.systemFailure, "error generating KEM encap key");
      }
      itvResp = new InfoTypeAndValue(infoType, new Asn1OctetString(encapKey.getEncoded()));
    }

    GenRepContent genRepContent = new GenRepContent(itvResp);
    return PKIBody.ofGenp(genRepContent);
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

    PKIFailureInfo failureInfo;
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

    return new PKIStatusInfo(PKIStatus.rejection, freeText, failureInfo);
  }

  protected static class EphemeralKeyPair {
    private KeyPair keyPair;
  }

  protected static class CmpVersion {
    private final int reqVersion;
    private int respVersion;

    private CmpVersion(PKIHeader reqHdr) {
      this.reqVersion = reqHdr.getPvno().intValueExact();
      this.respVersion = this.reqVersion;
    }
  }

}
