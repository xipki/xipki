// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.gateway.*;
import org.xipki.ca.gateway.api.Requestor;
import org.xipki.ca.gateway.api.RequestorAuthenticator;
import org.xipki.ca.sdk.*;
import org.xipki.cmp.CmpUtf8Pairs;
import org.xipki.cmp.CmpUtil;
import org.xipki.pki.ErrorCode;
import org.xipki.pki.OperationException;
import org.xipki.security.CrlReason;
import org.xipki.security.SecurityFactory;
import org.xipki.security.util.X509Util;
import org.xipki.util.DateUtil;
import org.xipki.util.Hex;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InsufficientPermissionException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.bouncycastle.asn1.cmp.PKIFailureInfo.*;
import static org.bouncycastle.asn1.cmp.PKIStatus.*;

/**
 * CMP responder.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CmpResponder extends BaseCmpResponder {

  private static final Logger LOG = LoggerFactory.getLogger(BaseCmpResponder.class);

  public CmpResponder(
      CmpControl cmpControl, SdkClient sdk, SecurityFactory securityFactory,
      CaNameSigners signers, RequestorAuthenticator authenticator, PopControl popControl)
      throws NoSuchAlgorithmException {
    super(cmpControl, sdk, securityFactory, signers, authenticator, popControl);
  }

  private CertRepMessage processCertReqMessages(
      String caName, String dfltCertprofileName, boolean groupEnroll, PKIMessage request,
      Requestor requestor, ASN1OctetString tid, CertReqMessages cr, AuditEvent event)
      throws InsufficientPermissionException, IOException, SdkErrorResponseException {
    CertReqMsg[] certReqMsgs = cr.toCertReqMsgArray();
    final int n = certReqMsgs.length;

    boolean reenroll = (request.getBody().getType() == PKIBody.TYPE_KEY_UPDATE_REQ);
    String[] certprofileNames = CmpUtil.extractCertProfile(request.getHeader().getGeneralInfo());

    int numCertprofileNames = certprofileNames == null ? 0 : certprofileNames.length;

    if (numCertprofileNames == 0) {
      certprofileNames = new String[n];
    } else if (numCertprofileNames < n) {
      certprofileNames = Arrays.copyOf(certprofileNames, n);
    }

    if (certprofileNames.length == n && StringUtil.isNotBlank(dfltCertprofileName)) {
      for (int i = 0; i < n; i++) {
        if (StringUtil.isBlank(certprofileNames[i])) {
          certprofileNames[i] = dfltCertprofileName;
        }
      }
    }

    boolean withNullProfileNames = false;
    for (int i = 0; i < n; i++) {
      if (StringUtil.isBlank(certprofileNames[i])) {
        withNullProfileNames = true;
        break;
      }
    }

    if (numCertprofileNames > n || // more cert profile names than allowed
        (!reenroll && withNullProfileNames)) { // cert profile names specified are not enough
      CertResponse[] certResps = new CertResponse[n];
      for (int i = 0; i < n; i++) {
        certResps[i] = new CertResponse(certReqMsgs[i].getCertReq().getCertReqId(),
            generateRejectionStatus(badCertTemplate, "number of specified cert profile names is not correct"));
      }

      event.setStatus(AuditStatus.FAILED);
      return new CertRepMessage(null, certResps);
    }

    List<EnrollCertsRequest.Entry> certTemplateDatas = new ArrayList<>(n);

    Map<Integer, CertResponse> failureResps = new HashMap<>();

    // pre-process requests
    for (int i = 0; i < n; i++) {
      CertReqMsg reqMsg = certReqMsgs[i];
      ASN1Integer certReqId = reqMsg.getCertReq().getCertReqId();
      CertificateRequestMessage req = new CertificateRequestMessage(reqMsg);
      CertTemplate certTemp = req.getCertTemplate();

      SubjectPublicKeyInfo publicKey = certTemp.getPublicKey();
      X500Name subject = certTemp.getSubject();

      OptionalValidity validity = certTemp.getValidity();

      Instant notBefore = null;
      Instant notAfter = null;
      if (validity != null) {
        if (validity.getNotBefore() != null) {
          notBefore = Instant.ofEpochMilli(validity.getNotBefore().getDate().getTime());
        }
        if (validity.getNotAfter() != null) {
          notAfter = Instant.ofEpochMilli(validity.getNotAfter().getDate().getTime());
        }
      }

      OldCertInfo.ByIssuerAndSerial oldCertInfo = null;

      if (reenroll) {
        // The regCtl-oldCertID will be ignored by calling
        // req.getControl(CMPObjectIdentifiers.regCtrl_oldCertID);
        Controls controls = reqMsg.getCertReq().getControls();
        AttributeTypeAndValue oldCertIdAtv = null;
        if (controls != null) {
          ASN1Sequence seq;
          try {
            seq = ASN1Sequence.getInstance(controls.getEncoded());
          } catch (IOException ex) {
            addErrCertResp(failureResps, i, certReqId, systemFailure, "could not parse the controls");
            continue;
          }

          final int seqSize = seq.size();
          for (int j = 0; j < seqSize; j++) {
            AttributeTypeAndValue atv = AttributeTypeAndValue.getInstance(seq.getObjectAt(j));
            if (atv.getType().equals(CMPObjectIdentifiers.regCtrl_oldCertID)) {
              oldCertIdAtv = atv;
              break;
            }
          }
        }

        if (oldCertIdAtv == null) {
          addErrCertResp(failureResps, i, certReqId, badCertTemplate, "no getCtrl oldCertID is specified");
          continue;
        }

        CertId oldCertId = CertId.getInstance(oldCertIdAtv.getValue());
        if (GeneralName.directoryName != oldCertId.getIssuer().getTagNo()) {
          addErrCertResp(failureResps, i, certReqId, badCertId, "invalid regCtrl oldCertID");
          continue;
        }

        oldCertInfo = new OldCertInfo.ByIssuerAndSerial(false,
            new X500NameType(oldCertId.getIssuer().getName().toASN1Primitive().getEncoded()),
            oldCertId.getSerialNumber().getValue());
      } // end if(reenroll)

      String certprofileName = certprofileNames[i];
      if (StringUtil.isNotBlank(certprofileName) && !requestor.isCertprofilePermitted(caName, certprofileName)) {
        addErrCertResp(failureResps, i, certReqId, notAuthorized,
            "certprofile " + certprofileName + " is not allowed");
        continue;
      }

      if (publicKey != null) {
        if (!req.hasProofOfPossession()) {
          addErrCertResp(failureResps, i, certReqId, badPOP, "no POP");
          continue;
        }

        if (!verifyPop(req, publicKey)) {
          LOG.warn("could not validate POP for request {}", certReqId.getValue());
          addErrCertResp(failureResps, i, certReqId, badPOP, "invalid POP");
          continue;
        }
      } else {
        checkPermission(requestor, Requestor.Permission.GEN_KEYPAIR);
      }

      EnrollCertsRequest.Entry template = new EnrollCertsRequest.Entry();
      template.setNotBefore(notBefore);
      template.setNotAfter(notAfter);
      template.setCertReqId(certReqId.getValue());
      if (StringUtil.isNotBlank(certprofileName)) {
        template.setCertprofile(certprofileName);
      }

      try {
        template.extensions(certTemp.getExtensions());
      } catch (IOException e) {
        LogUtil.warn(LOG, e, "could not encode extensions " + certReqId.getValue());
        addErrCertResp(failureResps, i, certReqId, badCertTemplate, "invalid extensions");
        continue;
      }

      if (publicKey != null) {
        try {
          template.setSubjectPublicKey(publicKey.getEncoded());
        } catch (IOException e) {
          LogUtil.warn(LOG, e, "could not encode extensions " + certReqId.getValue());
          addErrCertResp(failureResps, i, certReqId, badCertTemplate, "invalid public key");
          continue;
        }
      }

      if (subject != null) {
        template.setSubject(new X500NameType(subject));
      }

      if (oldCertInfo != null) {
        template.setOldCertIsn(oldCertInfo);
      }

      certTemplateDatas.add(template);
    } // end for

    if (certTemplateDatas.size() != n) {
      // at least one certRequest cannot be used to enroll certificate
      event.setStatus(AuditStatus.FAILED);

      CertResponse[] certResps = new CertResponse[n];
      for (int i = 0; i < n; i++) {
        certResps[i] = failureResps.get(i);
        if (certResps[i] == null) {
          certResps[i] = new CertResponse(certReqMsgs[i].getCertReq().getCertReqId(),
              generateRejectionStatus(badRequest, "failure in the parallel entries in the same request"));
        }
      }
      return new CertRepMessage(null, certResps);
    }

    boolean cross = request.getBody().getType() == PKIBody.TYPE_CROSS_CERT_REQ;
    return enrollCerts(caName, groupEnroll, reenroll, cross, requestor, tid,
        certTemplateDatas.toArray(new EnrollCertsRequest.Entry[0]), event);
  } // method processCertReqMessages

  /**
   * handle the PKI body with the choice {@code p10cr}<br/>
   * Since it is not possible to add attribute to the PKCS#10 request (CSR), the certificate
   * profile must be specified in the attribute regInfo-utf8Pairs (1.3.6.1.5.5.7.5.2.1) within
   * PKIHeader.generalInfo
   */
  private PKIBody processP10cr(
      String caName, String dfltCertprofileName, Requestor requestor, ASN1OctetString tid,
      PKIHeader reqHeader, CertificationRequest p10cr, AuditEvent event)
      throws SdkErrorResponseException {
    // verify the POP first
    CertRepMessage certResp;
    ASN1Integer certReqId = new ASN1Integer(-1);

    if (!GatewayUtil.verifyCsr(p10cr, securityFactory, popControl)) {
      LOG.warn("could not validate POP for the pkcs#10 requst");
      certResp = buildErrCertResp(certReqId, badPOP, "invalid POP");
    } else {
      InfoTypeAndValue[] generalInfo = reqHeader.getGeneralInfo();
      CmpUtf8Pairs keyvalues = CmpUtil.extractUtf8Pairs(generalInfo);

      // CertProfile name
      String certprofileName = null;
      String[] list = CmpUtil.extractCertProfile(generalInfo);
      if (list != null && list.length > 0) {
        certprofileName = list[0];
      }

      // NotBefore and NotAfter
      Instant notBefore = null;
      Instant notAfter = null;

      if (keyvalues != null) {
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
        certResp = buildErrCertResp(certReqId, badCertTemplate, "badCertTemplate");
      } else {
        certprofileName = certprofileName.toLowerCase();
        if (!requestor.isCertprofilePermitted(caName, certprofileName)) {
          String msg = "certprofile " + certprofileName + " is not allowed";
          certResp = buildErrCertResp(certReqId, notAuthorized, msg);
        } else {
          EnrollCertsRequest.Entry certTemplate = new EnrollCertsRequest.Entry();
          certTemplate.setCertprofile(certprofileName);
          certTemplate.setCertReqId(BigInteger.valueOf(-1));
          certTemplate.setNotBefore(notBefore);
          certTemplate.setNotAfter(notAfter);
          try {
            certTemplate.setP10req(p10cr.getEncoded());
          } catch (IOException e) {
            LogUtil.error(LOG, e);
            return buildErrorMsgPkiBody(rejection, badRequest, "invalid PKCS#10 request");
          }

          try {
            certResp = enrollCerts(caName, false, false, false, requestor, tid,
                new EnrollCertsRequest.Entry[]{certTemplate}, event);
          } catch (IOException e) {
            LogUtil.error(LOG, e);
            return buildErrorMsgPkiBody(rejection, systemFailure, null);
          }
        }
      }
    }

    if (event.getStatus() == null || event.getStatus() != AuditStatus.FAILED) {
      PKIStatusInfo statusObj = certResp.getResponse()[0].getStatus();
      int status = statusObj.getStatus().intValue();
      if (status != GRANTED && status != GRANTED_WITH_MODS && status != WAITING) {
        event.setStatus(AuditStatus.FAILED);
        PKIFreeText statusStr = statusObj.getStatusString();
        if (statusStr != null) {
          event.addEventData(CaAuditConstants.NAME_message, statusStr.getStringAtUTF8(0).getString());
        }
      }
    }

    return new PKIBody(PKIBody.TYPE_CERT_REP, certResp);
  } // method processP10cr

  private CertRepMessage enrollCerts(
      String caName, boolean groupEnroll, boolean reenroll, boolean cross, Requestor requestor,
      ASN1OctetString tid, EnrollCertsRequest.Entry[] templates, AuditEvent event)
      throws IOException, SdkErrorResponseException {
    String hexTid = Hex.encode(tid.getOctets());

    EnrollCertsRequest sdkReq = new EnrollCertsRequest();
    sdkReq.setExplicitConfirm(cmpControl.isConfirmCert());
    sdkReq.setGroupEnroll(groupEnroll);
    sdkReq.setConfirmWaitTimeMs((int) cmpControl.getConfirmWaitTime().toMillis());
    sdkReq.setCaCertMode(cmpControl.getCaCertsMode());
    sdkReq.setTransactionId(hexTid);
    sdkReq.setEntries(templates);

    for (EnrollCertsRequest.Entry m : templates) {
      event.addEventData(CaAuditConstants.NAME_certprofile, m.getCertprofile());
      X500Name subject = null;
      if (m.getSubject() != null) {
        subject = m.getSubject().toX500Name();
      } else if (m.getP10req() != null) {
        CertificationRequest csr;
        try {
          csr = GatewayUtil.parseCsrInRequest(m.getP10req());
        } catch (OperationException e) {
          throw new SdkErrorResponseException(ErrorCode.BAD_REQUEST, "error parsing PKCS#10 request");
        }
        subject = csr.getCertificationRequestInfo().getSubject();
      }
      if (subject != null) {
        event.addEventData(CaAuditConstants.NAME_req_subject, "\"" + X509Util.x500NameText(subject) + "\"");
      }
    }

    EnrollOrPollCertsResponse resp;
    if (cross) {
      resp = sdk.enrollCrossCerts(caName, sdkReq);
    } else {
      resp = reenroll ? sdk.reenrollCerts(caName, sdkReq) :sdk.enrollCerts(caName, sdkReq);
    }

    EnrollOrPollCertsResponse.Entry[] rentries = resp.getEntries();
    CertResponse[] certResponses = new CertResponse[rentries.length];
    for (int i = 0; i < rentries.length; i++) {
      EnrollOrPollCertsResponse.Entry respEntry = rentries[i];
      ErrorEntry error = respEntry.getError();
      if (error != null) {
        certResponses[i] = new CertResponse(new ASN1Integer(respEntry.getId()),
            buildPKIStatusInfo(error.getCode(), error.getMessage()));
      } else {
        certResponses[i] = postProcessCertInfo(new ASN1Integer(respEntry.getId()),
            requestor, respEntry.getCert(), respEntry.getPrivateKey());
      }
    }

    CMPCertificate[] caPubs = null;
    byte[][] extraCerts = resp.getExtraCerts();
    if (extraCerts != null && extraCerts.length > 0) {
      caPubs = new CMPCertificate[extraCerts.length];
      for (int i = 0; i < extraCerts.length; i++) {
        caPubs[i] = new CMPCertificate(Certificate.getInstance(extraCerts[i]));
      }
    }

    return new CertRepMessage(caPubs, certResponses);
  }

  private PKIBody unRevokeCertificates(RevReqContent rr, boolean revoke, AuditEvent event)
      throws IOException, SdkErrorResponseException {
    RevDetails[] revContent = rr.toRevDetailsArray();
    if (revContent == null || revContent.length == 0) {
      return buildErrorMsgPkiBody(rejection, badRequest, "no entry is specified");
    }

    List<RevokeCertsRequest.Entry> revokeEntries = revoke ? new ArrayList<>(revContent.length) : null;
    List<BigInteger> unrevokeEntries = revoke ? null : new ArrayList<>(revContent.length);
    X500Name issuer = null;
    byte[] aki = null;

    for (RevDetails revDetails : revContent) {
      CertTemplate certDetails = revDetails.getCertDetails();
      X500Name tIssuer = certDetails.getIssuer();
      if (tIssuer == null) {
        return buildErrorMsgPkiBody(rejection, badCertTemplate, "issuer is not present");
      }

      if (issuer == null) {
        issuer = tIssuer;
      } else if (!issuer.equals(tIssuer)) {
        return buildErrorMsgPkiBody(rejection, badCertTemplate, "not all issuers are of the same");
      }

      if (certDetails.getSerialNumber() == null) {
        return buildErrorMsgPkiBody(rejection, badCertTemplate, "serialNumber is not present");
      }

      BigInteger serialNumber = certDetails.getSerialNumber().getValue();

      if (certDetails.getSigningAlg() != null || certDetails.getValidity() != null
          || certDetails.getSubject() != null || certDetails.getPublicKey() != null
          || certDetails.getIssuerUID() != null || certDetails.getSubjectUID() != null) {
        return buildErrorMsgPkiBody(rejection, badCertTemplate,
            "only version, issuer and serialNumber in RevDetails.certDetails are allowed, but more is specified");
      }

      // authorityKeyIdentifier
      if (certDetails.getExtensions() != null) {
        Extensions exts = certDetails.getExtensions();
        ASN1ObjectIdentifier[] oids = exts.getCriticalExtensionOIDs();
        if (oids != null) {
          for (ASN1ObjectIdentifier oid : oids) {
            if (!Extension.authorityKeyIdentifier.equals(oid)) {
              return buildErrorMsgPkiBody(rejection, badCertTemplate, "unknown critical extension " + oid.getId());
            }
          }
        }

        Extension ext = exts.getExtension(Extension.authorityKeyIdentifier);
        if (ext != null) {
          AuthorityKeyIdentifier tAki = AuthorityKeyIdentifier.getInstance(ext.getParsedValue());
          if (tAki.getKeyIdentifier() == null) {
            return buildErrorMsgPkiBody(rejection, badCertTemplate, "issuer's AKI not present");
          }

          if (aki == null) {
            aki = tAki.getKeyIdentifier();
          } else if (!Arrays.equals(aki, tAki.getKeyIdentifier())) {
            return buildErrorMsgPkiBody(rejection, badCertTemplate, "not all AKIs are of the same");
          }
        }
      }

      if (revoke) {
        Instant invalidityDate = null;
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
              invalidityDate = ASN1GeneralizedTime.getInstance(extValue).getDate().toInstant();
            } catch (ParseException ex) {
              return buildErrorMsgPkiBody(rejection, badCertTemplate, "invalid extension InvalidityDate");
            }
          }
        } // end if (crlDetails)

        if (reason == null) {
          reason = CrlReason.UNSPECIFIED;
        }
        event.addEventData(CaAuditConstants.NAME_reason, reason);

        revokeEntries.add(new RevokeCertsRequest.Entry(serialNumber, reason, invalidityDate));
      } else {
        unrevokeEntries.add(serialNumber);
      }
      event.addEventData(CaAuditConstants.NAME_serial, LogUtil.formatCsn(serialNumber));
    }

    SingleCertSerialEntry[] respEntries;

    X500NameType issuerType = new X500NameType(issuer);
    if (revoke) {
      RevokeCertsRequest req = new RevokeCertsRequest(
          null, issuerType, aki, revokeEntries.toArray(new RevokeCertsRequest.Entry[0]));
      RevokeCertsResponse resp = sdk.revokeCerts(req);
      respEntries = resp.getEntries();
    } else {
      UnsuspendOrRemoveCertsRequest req = new UnsuspendOrRemoveCertsRequest(
          null, issuerType, aki, unrevokeEntries.toArray(new BigInteger[0]));
      UnSuspendOrRemoveCertsResponse resp = sdk.unsuspendCerts(req);
      respEntries = resp.getEntries();
    }

    GeneralName caGn = new GeneralName(issuer);
    RevRepContentBuilder repContentBuilder = new RevRepContentBuilder();
    for (SingleCertSerialEntry m : respEntries) {
      ErrorEntry error = m.getError();

      PKIStatusInfo status = error == null ? new PKIStatusInfo(granted)
          : buildPKIStatusInfo(error.getCode(), error.getMessage());

      repContentBuilder.add(status, new CertId(caGn, m.getSerialNumber()));
    }

    return new PKIBody(PKIBody.TYPE_REVOCATION_REP, repContentBuilder.build());
  } // method unRevokeCertificates

  @Override
  protected PKIBody confirmCertificates(
      String caName, ASN1OctetString transactionId, CertConfirmContent certConf)
      throws SdkErrorResponseException {
    CertStatus[] certStatuses = certConf.toCertStatusArray();

    ConfirmCertsRequest.Entry[] entries = new ConfirmCertsRequest.Entry[certStatuses.length];

    for (int i = 0; i < entries.length; i++) {
      CertStatus certStatus = certStatuses[i];
      PKIStatusInfo statusInfo = certStatus.getStatusInfo();
      boolean accept = true;
      if (statusInfo != null) {
        int status = statusInfo.getStatus().intValue();
        if (GRANTED != status && GRANTED_WITH_MODS != status) {
          accept = false;
        }
      }

      entries[i] = new ConfirmCertsRequest.Entry(accept,
          certStatus.getCertReqId().getValue(), certStatus.getCertHash().getOctets());
    }

    ConfirmCertsRequest sdkReq = new ConfirmCertsRequest(Hex.encode(transactionId.getOctets()), entries);

    sdk.confirmCerts(caName, sdkReq);
    return new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
  } // method confirmCertificates

  @Override
  protected PKIBody revokePendingCertificates(String caName, ASN1OctetString transactionId)
      throws SdkErrorResponseException {
    sdk.revokePendingCerts(caName, Hex.encode(transactionId.getOctets()));
    return new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
  }

  @Override
  protected PKIBody cmpEnrollCert(
      String caName, String dfltCertprofileName, boolean groupEnroll,
      PKIMessage request, PKIHeaderBuilder respHeader, PKIHeader reqHeader, PKIBody reqBody,
      Requestor requestor, ASN1OctetString tid, AuditEvent event)
      throws InsufficientPermissionException, SdkErrorResponseException {
    if (dfltCertprofileName != null) {
      dfltCertprofileName = dfltCertprofileName.toLowerCase(Locale.ROOT);
    }

    Duration confirmWaitTime = cmpControl.getConfirmWaitTime();

    PKIBody respBody;

    int type = reqBody.getType();
    try {
      switch (type) {
        case PKIBody.TYPE_INIT_REQ: {
          checkPermission(requestor, Requestor.Permission.ENROLL_CERT);
          CertReqMessages cr = CertReqMessages.getInstance(reqBody.getContent());
          CertRepMessage repMessage = processCertReqMessages(
              caName, dfltCertprofileName, groupEnroll, request, requestor, tid, cr, event);
          respBody = new PKIBody(PKIBody.TYPE_INIT_REP, repMessage);
          break;
        }
        case PKIBody.TYPE_CERT_REQ: {
          checkPermission(requestor, Requestor.Permission.ENROLL_CERT);
          CertReqMessages cr = CertReqMessages.getInstance(reqBody.getContent());
          CertRepMessage repMessage = processCertReqMessages(
              caName, dfltCertprofileName, groupEnroll, request, requestor, tid, cr, event);
          respBody = new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
          break;
        }
        case PKIBody.TYPE_KEY_UPDATE_REQ: {
          checkPermission(requestor, Requestor.Permission.REENROLL_CERT);
          CertReqMessages kur = CertReqMessages.getInstance(reqBody.getContent());
          CertRepMessage repMessage = processCertReqMessages(
              caName, dfltCertprofileName, groupEnroll, request, requestor, tid, kur, event);
          respBody = new PKIBody(PKIBody.TYPE_KEY_UPDATE_REP, repMessage);
          break;
        }
        case PKIBody.TYPE_P10_CERT_REQ: {
          checkPermission(requestor, Requestor.Permission.ENROLL_CERT);
          respBody = processP10cr(caName, dfltCertprofileName, requestor, tid, reqHeader,
              GatewayUtil.parseCsrInRequest(reqBody.getContent()), event);
          break;
        }
        case PKIBody.TYPE_CROSS_CERT_REQ: {
          checkPermission(requestor, Requestor.Permission.ENROLL_CROSS);
          CertReqMessages cr = CertReqMessages.getInstance(reqBody.getContent());
          CertRepMessage repMessage = processCertReqMessages(
              caName, dfltCertprofileName, groupEnroll, request, requestor, tid, cr, event);
          respBody = new PKIBody(PKIBody.TYPE_CROSS_CERT_REP, repMessage);
          break;
        }
        default:
          throw new IllegalStateException("should not reach here");
      } // switch type
    } catch (OperationException | IOException e) {
      LogUtil.error(LOG, e);
      return buildErrorMsgPkiBody(rejection, systemFailure, null);
    }

    // TODO: evaluate the confirm and confirmTime of the response
    InfoTypeAndValue tv;
    if (!cmpControl.isConfirmCert() && CmpUtil.isImplicitConfirm(reqHeader)) {
      tv = CmpUtil.getImplicitConfirmGeneralInfo();
    } else {
      Instant now = Instant.now();
      respHeader.setMessageTime(new ASN1GeneralizedTime(Date.from(now)));
      tv = new InfoTypeAndValue(CMPObjectIdentifiers.it_confirmWaitTime,
          new ASN1GeneralizedTime(Date.from((Instant) confirmWaitTime.addTo(now))));
    }

    respHeader.setGeneralInfo(tv);
    return respBody;
  } // method cmpEnrollCert

  @Override
  protected PKIBody cmpUnRevokeCertificates(
      String caName, PKIMessage request, PKIHeaderBuilder respHeader,
      PKIHeader reqHeader, PKIBody reqBody, Requestor requestor, AuditEvent event)
      throws SdkErrorResponseException {
    RevReqContent rr = RevReqContent.getInstance(reqBody.getContent());
    RevDetails[] revContent = rr.toRevDetailsArray();
    if (revContent == null || revContent.length == 0) {
      return buildErrorMsgPkiBody(rejection, badRequest, "no entry is specified");
    }

    Requestor.Permission requiredPermission = null;
    boolean allRevdetailsOfSameType = true;

    for (RevDetails revDetails : revContent) {
      Extensions crlDetails = revDetails.getCrlEntryDetails();
      int reasonCode = CrlReason.UNSPECIFIED.getCode();
      if (crlDetails != null) {
        ASN1ObjectIdentifier extId = Extension.reasonCode;
        ASN1Encodable extValue = crlDetails.getExtensionParsedValue(extId);
        if (extValue != null) {
          reasonCode = ASN1Enumerated.getInstance(extValue).getValue().intValue();
        }
      }

      /*
        unspecified             (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
             -- value 7 is not used
        removeFromCRL           (8),
        privilegeWithdrawn      (9),
        aACompromise           (10)
       */
      if (reasonCode < 0 || reasonCode > 10 || reasonCode == 7) {
        return buildErrorMsgPkiBody(rejection, badRequest, "invalid CRLReason " + reasonCode);
      }

      if (reasonCode == CrlReason.REMOVE_FROM_CRL.getCode()) {
        if (requiredPermission == null) {
          event.addEventType(TYPE_rr_unrevoke);
          requiredPermission = Requestor.Permission.UNSUSPEND_CERT;
        } else if (requiredPermission != Requestor.Permission.UNSUSPEND_CERT) {
          allRevdetailsOfSameType = false;
          break;
        }
      } else {
        if (requiredPermission == null) {
          event.addEventType(TYPE_rr_revoke);
          requiredPermission = Requestor.Permission.REVOKE_CERT;
        } else if (requiredPermission != Requestor.Permission.REVOKE_CERT) {
          allRevdetailsOfSameType = false;
          break;
        }
      }
    } // end for

    if (!allRevdetailsOfSameType) {
      ErrorMsgContent emc = new ErrorMsgContent(
          new PKIStatusInfo(rejection, new PKIFreeText("not all revDetails are of the same type"),
          new PKIFailureInfo(badRequest)));

      return new PKIBody(PKIBody.TYPE_ERROR, emc);
    }

    try {
      checkPermission(requestor, requiredPermission);
    } catch (InsufficientPermissionException ex) {
      event.setStatus(AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, "NOT_PERMITTED");
      return buildErrorMsgPkiBody(rejection, notAuthorized, null);
    }

    boolean revoke = requiredPermission == Requestor.Permission.REVOKE_CERT;
    try {
      return unRevokeCertificates(rr, revoke, event);
    } catch (IOException e) {
      LogUtil.error(LOG, e);
      return buildErrorMsgPkiBody(rejection, systemFailure, null);
    }
  } // method cmpUnRevokeCertificates

}
