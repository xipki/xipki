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

package org.xipki.ca.server.cmp;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.mgmt.api.CmpControl;
import org.xipki.ca.mgmt.api.RequestorInfo;
import org.xipki.ca.server.CaAuditConstants;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.cmp.CmpUtil;
import org.xipki.security.cmp.ProtectionResult;
import org.xipki.security.cmp.ProtectionVerificationResult;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.LogUtil;
import org.xipki.util.RandomUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class BaseCmpResponder {

  private static final Logger LOG = LoggerFactory.getLogger(BaseCmpResponder.class);

  private static final int PVNO_CMP2000 = 2;

  protected final SecurityFactory securityFactory;

  private final SecureRandom random = new SecureRandom();

  protected BaseCmpResponder(SecurityFactory securityFactory) {
    this.securityFactory = Args.notNull(securityFactory, "securityFactory");
  }

  protected abstract ConcurrentContentSigner getSigner();

  protected abstract GeneralName getSender();

  protected abstract boolean intendsMe(GeneralName requestRecipient);

  public boolean isOnService() {
    try {
      return getSigner() != null;
    } catch (Exception ex) {
      LogUtil.error(LOG, ex, "could not get responder signer");
      return false;
    }
  }

  /**
   * TODO.
   * @return never returns {@code null}.
   */
  protected abstract CmpControl getCmpControl();

  // CHECKSTYLE:SKIP
  public abstract CmpRequestorInfo getMacRequestor(X500Name requestorSender, byte[] senderKID);

  public abstract CmpRequestorInfo getRequestor(X500Name requestorSender);

  public abstract CmpRequestorInfo getRequestor(X509Certificate requestorCert);

  private static X500Name getX500Sender(PKIHeader reqHeader) {
    GeneralName requestSender = reqHeader.getSender();
    if (requestSender.getTagNo() != GeneralName.directoryName) {
      return null;
    }

    return (X500Name) requestSender.getName();
  }

  /**
   * Processes the request and returns the response.
   * @param request
   *          Original request. Will only be used for the storage. Could be{@code null}.
   * @param requestor
   *          Requestor. Must not be {@code null}.
   * @param transactionId
   *          Transaction id. Must not be {@code null}.
   * @param pkiMessage
   *          PKI message. Must not be {@code null}.
   * @param msgId
   *          Message id. Must not be {@code null}.
   * @param parameters
   *          Additional parameters.
   * @param event
   *          Audit event. Must not be {@code null}.
   * @return the response
   */
  protected abstract PKIMessage processPkiMessage0(PKIMessage request, RequestorInfo requestor,
      ASN1OctetString transactionId, GeneralPKIMessage pkiMessage, String msgId,
      Map<String, String> parameters, AuditEvent event);

  public PKIMessage processPkiMessage(PKIMessage pkiMessage, X509Certificate tlsClientCert,
      Map<String, String> parameters, AuditEvent event) {
    Args.notNull(pkiMessage, "pkiMessage");
    Args.notNull(event, "event");
    GeneralPKIMessage message = new GeneralPKIMessage(pkiMessage);

    PKIHeader reqHeader = message.getHeader();
    ASN1OctetString tid = reqHeader.getTransactionID();

    String msgId = null;
    if (event != null) {
      msgId = RandomUtil.nextHexLong();
      event.addEventData(CaAuditConstants.NAME_mid, msgId);
    }

    if (tid == null) {
      byte[] randomBytes = randomTransactionId();
      tid = new DEROctetString(randomBytes);
    }
    String tidStr = Base64.encodeToString(tid.getOctets());
    if (event != null) {
      event.addEventData(CaAuditConstants.NAME_tid, tidStr);
    }

    int reqPvno = reqHeader.getPvno().getValue().intValue();
    if (reqPvno != PVNO_CMP2000) {
      if (event != null) {
        event.setLevel(AuditLevel.INFO);
        event.setStatus(AuditStatus.FAILED);
        event.addEventData(CaAuditConstants.NAME_message, "unsupproted version " + reqPvno);
      }
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
    boolean intentMe = (recipient == null) ? true : intendsMe(recipient);
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
      if (event != null) {
        event.setLevel(AuditLevel.INFO);
        event.setStatus(AuditStatus.FAILED);
        event.addEventData(CaAuditConstants.NAME_message, statusText);
      }
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
            throw new IllegalStateException(
                "should not reach here, unknown ProtectionResult " + pr);
        } // end switch
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
            X509Util.getRfc4519Name(tlsClientCert.getSubjectX500Principal()));
        errorStatus = "requestor (TLS client certificate) is not authorized";
      }
    } else {
      errorStatus = "request has no protection";
      requestor = null;
    }

    if (errorStatus != null) {
      if (event != null) {
        event.setLevel(AuditLevel.INFO);
        event.setStatus(AuditStatus.FAILED);
        event.addEventData(CaAuditConstants.NAME_message, errorStatus);
      }
      return buildErrorPkiMessage(tid, reqHeader, PKIFailureInfo.badMessageCheck, errorStatus);
    }

    PKIMessage resp = processPkiMessage0(pkiMessage, requestor, tid, message, msgId, parameters,
        event);

    if (isProtected) {
      resp = addProtection(resp, event, requestor);
    } else {
      // protected by TLS connection
    }

    return resp;
  } // method processPkiMessage

  protected byte[] randomTransactionId() {
    return randomBytes(10);
  }

  protected byte[] randomSalt() {
    return randomBytes(64);
  }

  protected byte[] randomBytes(int len) {
    byte[] bytes = new byte[len];
    random.nextBytes(bytes);
    return bytes;
  }

  private ProtectionVerificationResult verifyProtection(String tid, GeneralPKIMessage pkiMessage,
      CmpControl cmpControl) throws CMPException, InvalidKeyException, OperatorCreationException {
    ProtectedPKIMessage protectedMsg = new ProtectedPKIMessage(pkiMessage);

    PKIHeader header = protectedMsg.getHeader();
    X500Name sender = getX500Sender(header);
    if (sender == null) {
      LOG.warn("tid={}: not authorized requestor 'null'", tid);
      return new ProtectionVerificationResult(null, ProtectionResult.SENDER_NOT_AUTHORIZED);
    }

    AlgorithmIdentifier protectionAlg = header.getProtectionAlg();

    if (protectedMsg.hasPasswordBasedMacProtection()) {
      PBMParameter parameter =
          PBMParameter.getInstance(pkiMessage.getHeader().getProtectionAlg().getParameters());
      AlgorithmIdentifier algId = parameter.getOwf();
      if (!cmpControl.isRequestPbmOwfPermitted(algId)) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.owf: {})", algId.getAlgorithm().getId());
        return new ProtectionVerificationResult(null, ProtectionResult.MAC_ALGO_FORBIDDEN);
      }

      algId = parameter.getMac();
      if (!cmpControl.isRequestPbmMacPermitted(algId)) {
        LOG.warn("MAC_ALGO_FORBIDDEN (PBMParameter.mac: {})", algId.getAlgorithm().getId());
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

      CmpRequestorInfo requestor = getMacRequestor(sender, senderKID);

      if (requestor == null) {
        LOG.warn("tid={}: not authorized requestor '{}' with senderKID '{}", tid, sender,
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
      } else {
        PBMParameter parameter = new PBMParameter(randomSalt(), control.getResponsePbmOwf(),
            control.getResponsePbmIterationCount(), control.getResponsePbmMac());
        return CmpUtil.addProtection(pkiMessage, requestor.getPassword(), parameter,
            getSender(), requestor.getKeyId());
      }
    } catch (Exception ex) {
      LogUtil.error(LOG, ex, "could not add protection to the PKI message");
      PKIStatusInfo status = generateRejectionStatus(
          PKIFailureInfo.systemFailure, "could not sign the PKIMessage");

      event.setLevel(AuditLevel.ERROR);
      event.setStatus(AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, "could not sign the PKIMessage");
      PKIBody body = new PKIBody(PKIBody.TYPE_ERROR, new ErrorMsgContent(status));
      return new PKIMessage(pkiMessage.getHeader(), body);
    }
  } // method addProtection

  protected PKIMessage buildErrorPkiMessage(ASN1OctetString tid,
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

  protected PKIStatusInfo generateRejectionStatus(Integer info, String errorMessage) {
    return generateRejectionStatus(PKIStatus.rejection, info, errorMessage);
  } // method generateCmpRejectionStatus

  protected PKIStatusInfo generateRejectionStatus(PKIStatus status, Integer info,
      String errorMessage) {
    PKIFreeText statusMessage = (errorMessage == null) ? null : new PKIFreeText(errorMessage);
    PKIFailureInfo failureInfo = (info == null) ? null : new PKIFailureInfo(info);
    return new PKIStatusInfo(status, statusMessage, failureInfo);
  } // method generateCmpRejectionStatus

  public X500Name getResponderSubject() {
    GeneralName sender = getSender();
    return (sender == null) ? null : (X500Name) sender.getName();
  }

  public X509Certificate getResponderCert() {
    ConcurrentContentSigner signer = getSigner();
    return (signer == null) ? null : signer.getCertificate();
  }

}
