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
import org.xipki.ca.sdk.*;
import org.xipki.security.CrlReason;
import org.xipki.security.DHSigStaticKeyCertPair;
import org.xipki.security.SecurityFactory;
import org.xipki.security.cmp.CmpUtf8Pairs;
import org.xipki.security.cmp.CmpUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.DateUtil;
import org.xipki.util.*;
import org.xipki.util.exception.InsufficientPermissionException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.*;

import static org.bouncycastle.asn1.cmp.PKIFailureInfo.*;
import static org.bouncycastle.asn1.cmp.PKIStatus.*;

/**
 * CMP responder.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class CmpResponder extends BaseCmpResponder {

  private static final Logger LOG = LoggerFactory.getLogger(BaseCmpResponder.class);

  public CmpResponder(
      CmpControl cmpControl, SdkClient sdk, SecurityFactory securityFactory,
      CaNameSigners signers, RequestorAuthenticator authenticator,
      PopControl popControl)
      throws NoSuchAlgorithmException {
    super(cmpControl, sdk, securityFactory, signers, authenticator, popControl);
  }

  private CertRepMessage processCertReqMessages(
      String caName, String dfltCertprofileName, boolean groupEnroll,
      PKIMessage request, Requestor requestor,
      ASN1OctetString tid, CertReqMessages cr, AuditEvent event)
      throws InsufficientPermissionException, IOException, SdkErrorResponseException {
    CertReqMsg[] certReqMsgs = cr.toCertReqMsgArray();
    final int n = certReqMsgs.length;

    String[] certprofileNames = CmpUtil.extractCertProfile(request.getHeader().getGeneralInfo());
    if (certprofileNames == null) {
      if (dfltCertprofileName != null) {
        certprofileNames = new String[n];

        for (int i = 0; i < n; i++) {
          certprofileNames[i] = dfltCertprofileName;
        }
      }
    }

    boolean kup = (request.getBody().getType() == PKIBody.TYPE_KEY_UPDATE_REQ);
    int numCertprofileNames = (certprofileNames == null) ? 0 : certprofileNames.length;
    if (!((numCertprofileNames == n) || (kup && numCertprofileNames == 0))) {
      CertResponse[] certResps = new CertResponse[n];
      for (int i = 0; i < n; i++) {
        ASN1Integer certReqId = certReqMsgs[i].getCertReq().getCertReqId();
        String msg = "expected " + n + ", but " + numCertprofileNames
            + " CertProfile names are specified";
        certResps[i] = new CertResponse(certReqId, generateRejectionStatus(badCertTemplate, msg));
      }

      event.setStatus(AuditStatus.FAILED);
      return new CertRepMessage(null, certResps);
    }

    List<EnrollCertRequestEntry> certTemplateDatas = new ArrayList<>(n);

    Map<Integer, CertResponse> failureResps = new HashMap<>();

    // pre-process requests
    for (int i = 0; i < n; i++) {
      CertReqMsg reqMsg = certReqMsgs[i];
      ASN1Integer certReqId = reqMsg.getCertReq().getCertReqId();
      CertificateRequestMessage req = new CertificateRequestMessage(reqMsg);
      CertTemplate certTemp = req.getCertTemplate();

      SubjectPublicKeyInfo publicKey = certTemp.getPublicKey();
      X500Name subject = certTemp.getSubject();

      // till version 5.3.13, UTF8Pairs is used to specify the CertProfile
      String certprofileName = certprofileNames == null ? null : certprofileNames[i];

      OptionalValidity validity = certTemp.getValidity();

      Long notBefore = null;
      Long notAfter = null;
      if (validity != null) {
        if (validity.getNotBefore() != null) {
          notBefore = validity.getNotBefore().getDate().getTime() / 1000;
        }
        if (validity.getNotAfter() != null) {
          notAfter = validity.getNotAfter().getDate().getTime() / 1000;
        }
      }

      OldCertInfo oldCertInfo = null;

      if (kup) {
        // The regCtl-oldCertID will be ignored by calling
        // req.getControl(CMPObjectIdentifiers.regCtrl_oldCertID);
        Controls controls = reqMsg.getCertReq().getControls();
        AttributeTypeAndValue oldCertIdAtv = null;
        if (controls != null) {
          ASN1Sequence seq;
          try {
            seq = ASN1Sequence.getInstance(controls.getEncoded());
          } catch (IOException ex) {
            addErrCertResp(failureResps, i, certReqId, systemFailure,
                "could not parse the controls");
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
          addErrCertResp(failureResps, i, certReqId, badCertTemplate,
              "no getCtrl oldCertID is specified");
          continue;
        }

        CertId oldCertId = CertId.getInstance(oldCertIdAtv.getValue());
        if (GeneralName.directoryName != oldCertId.getIssuer().getTagNo()) {
          addErrCertResp(failureResps, i, certReqId, badCertId, "invalid regCtrl oldCertID");
          continue;
        }
        if (!requestor.isCertprofilePermitted(certprofileName)) {
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
          checkPermission(requestor, PermissionConstants.GEN_KEYPAIR);
        }

        oldCertInfo = new OldCertInfo();
        oldCertInfo.setIssuer(
            new X500NameType(X500Name.getInstance(oldCertId.getIssuer().getName())));
        oldCertInfo.setSerialNumber(oldCertId.getSerialNumber().getValue());
        oldCertInfo.setReusePublicKey(false);
      }

      EnrollCertRequestEntry template = new EnrollCertRequestEntry();
      template.setNotBefore(notBefore);
      template.setNotAfter(notAfter);
      template.setCertReqId(certReqId.getValue());
      template.setCertprofile(certprofileName);

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

      template.setSubject(new X500NameType(subject));

      if (oldCertInfo != null) {
        template.setOldCert(oldCertInfo);
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
              generateRejectionStatus(badRequest,
                  "failure in the parallel entries in the same request"));
        }
      }
      return new CertRepMessage(null, certResps);
    }

    boolean cross = request.getBody().getType() == PKIBody.TYPE_CROSS_CERT_REQ;
    return enrollCerts(caName, groupEnroll, kup, cross, requestor, tid, certTemplateDatas, event);
  } // method processCertReqMessages

  /**
   * handle the PKI body with the choice {@code p10cr}<br/>
   * Since it is not possible to add attribute to the PKCS#10 request (CSR), the certificate
   * profile must be specified in the attribute regInfo-utf8Pairs (1.3.6.1.5.5.7.5.2.1) within
   * PKIHeader.generalInfo
   */
  private PKIBody processP10cr(String caName, String dfltCertprofileName,
                               Requestor requestor, ASN1OctetString tid, PKIHeader reqHeader,
                               CertificationRequest p10cr, AuditEvent event)
      throws SdkErrorResponseException {
    // verify the POP first
    CertRepMessage certResp;
    ASN1Integer certReqId = new ASN1Integer(-1);

    if (!SdkClient.verifyCsr(p10cr, securityFactory, popControl)) {
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
      Long notBefore = null;
      Long notAfter = null;

      if (keyvalues != null) {
        String str = keyvalues.value(CmpUtf8Pairs.KEY_NOTBEFORE);
        if (str != null) {
          notBefore = DateUtil.parseUtcTimeyyyyMMddhhmmss(str).getTime() / 1000;
        }

        str = keyvalues.value(CmpUtf8Pairs.KEY_NOTAFTER);
        if (str != null) {
          notAfter = DateUtil.parseUtcTimeyyyyMMddhhmmss(str).getTime() / 1000;
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
        if (!requestor.isCertprofilePermitted(certprofileName)) {
          String msg = "certprofile " + certprofileName + " is not allowed";
          certResp = buildErrCertResp(certReqId, notAuthorized, msg);
        } else {
          EnrollCertRequestEntry certTemplate = new EnrollCertRequestEntry();
          certTemplate.setCertprofile(certprofileName);
          certTemplate.setCertReqId(BigInteger.valueOf(-1));
          certTemplate.setNotBefore(notBefore);
          certTemplate.setNotAfter(notAfter);
          try {
            certTemplate.setP10req(p10cr.getEncoded());
          } catch (IOException e) {
            LogUtil.error(LOG, e);
            return buildErrorMsgPkiBody(rejection, badRequest,
                "invalid PKCS#10 request");
          }

          try {
            certResp = enrollCerts(caName, false, false, false, requestor, tid,
                Collections.singletonList(certTemplate), event);
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
          event.addEventData(CaAuditConstants.NAME_message,
              statusStr.getStringAtUTF8(0).getString());
        }
      }
    }

    return new PKIBody(PKIBody.TYPE_CERT_REP, certResp);
  } // method processP10cr

  private CertRepMessage enrollCerts(
      String caName, boolean groupEnroll, boolean kup, boolean cross, Requestor requestor,
      ASN1OctetString tid, List<EnrollCertRequestEntry> templates, AuditEvent event)
      throws IOException, SdkErrorResponseException {
    EnrollCertsRequest sdkReq = new EnrollCertsRequest();
    sdkReq.setExplicitConfirm(cmpControl.isConfirmCert());
    sdkReq.setGroupEnroll(groupEnroll);
    sdkReq.setConfirmWaitTimeMs(cmpControl.getConfirmWaitTimeMs());
    sdkReq.setCaCertMode(cmpControl.getCaCertsMode());
    sdkReq.setTransactionId(Hex.encode(tid.getOctets()));
    sdkReq.setEntries(templates);

    for (EnrollCertRequestEntry m : templates) {
      event.addEventData(CaAuditConstants.NAME_certprofile, m.getCertprofile());
      X500Name subject;
      if (m.getSubject() != null) {
        subject = m.getSubject().toX500Name();
      } else {
        CertificationRequest csr = CertificationRequest.getInstance(m.getP10req());
        subject = csr.getCertificationRequestInfo().getSubject();
      }
      event.addEventData(CaAuditConstants.NAME_req_subject,
          "\"" + X509Util.x500NameText(subject) + "\"");
    }

    EnrollOrPollCertsResponse resp;
    if (cross) {
      resp = sdk.enrollCrossCerts(caName, sdkReq);
    } else {
      resp = kup ? sdk.enrollKupCerts(caName, sdkReq) :sdk.enrollCerts(caName, sdkReq);
    }

    List<EnrollOrPullCertResponseEntry> rentries = resp.getEntries();
    CertResponse[] certResponses = new CertResponse[rentries.size()];
    for (int i = 0; i < rentries.size(); i++) {
      EnrollOrPullCertResponseEntry respEntry = rentries.get(i);
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
    List<byte[]> extraCerts = resp.getExtraCerts();
    if (CollectionUtil.isNotEmpty(extraCerts)) {
      List<CMPCertificate> certchain = new ArrayList<>(extraCerts.size());
      for (byte[] m : extraCerts) {
        certchain.add(new CMPCertificate(Certificate.getInstance(m)));
      }
      caPubs = certchain.toArray(new CMPCertificate[0]);
    }

    return new CertRepMessage(caPubs, certResponses);
  }

  private PKIBody unRevokeCertificates(String caName, RevReqContent rr,
      boolean revoke, AuditEvent event) throws IOException, SdkErrorResponseException {
    RevDetails[] revContent = rr.toRevDetailsArray();

    List<RevokeCertRequestEntry> revokeEntries = revoke ? new ArrayList<>(revContent.length) : null;
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
      } else if (issuer.equals(tIssuer)) {
        return buildErrorMsgPkiBody(rejection, badCertTemplate, "not all issuers are of the same");
      }

      if (certDetails.getSerialNumber() == null) {
        return buildErrorMsgPkiBody(rejection, badCertTemplate, "serialNumber is not present");
      }

      BigInteger serialNumber = certDetails.getSerialNumber().getValue();

      if (certDetails.getSigningAlg() != null || certDetails.getValidity() != null
          || certDetails.getSubject() != null || certDetails.getPublicKey() != null
          || certDetails.getIssuerUID() != null || certDetails.getSubjectUID() != null) {
        return buildErrorMsgPkiBody(rejection, badCertTemplate, "only version, issuer and "
            + "serialNumber in RevDetails.certDetails are allowed, but more is specified");
      }

      // authorityKeyIdentifier
      if (certDetails.getExtensions() != null) {
        Extensions exts = certDetails.getExtensions();
        ASN1ObjectIdentifier[] oids = exts.getCriticalExtensionOIDs();
        if (oids != null) {
          for (ASN1ObjectIdentifier oid : oids) {
            if (!Extension.authorityKeyIdentifier.equals(oid)) {
              return buildErrorMsgPkiBody(rejection, badCertTemplate,
                  "unknown critical extension " + oid.getId());
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
              return buildErrorMsgPkiBody(rejection, badCertTemplate,
                  "invalid extension InvalidityDate");
            }
          }
        } // end if (crlDetails)

        if (reason == null) {
          reason = CrlReason.UNSPECIFIED;
        }
        event.addEventData(CaAuditConstants.NAME_reason, reason);

        RevokeCertRequestEntry entry = new RevokeCertRequestEntry();
        entry.setSerialNumber(serialNumber);
        entry.setReason(reason);
        if (invalidityDate != null) {
          entry.setInvalidityTime(invalidityDate.getTime() / 1000);
        }
        revokeEntries.add(entry);
      } else {
        unrevokeEntries.add(serialNumber);
      }
      event.addEventData(CaAuditConstants.NAME_serial, LogUtil.formatCsn(serialNumber));
    }

    List<SingleCertSerialEntry> respEntries;

    if (revoke) {
      RevokeCertsRequest req = new RevokeCertsRequest();
      req.setEntries(revokeEntries);
      req.setIssuer(new X500NameType(issuer));
      req.setAuthorityKeyIdentifier(aki);
      RevokeCertsResponse resp = sdk.revokeCerts(caName, req);
      respEntries = resp.getEntries();
    } else {
      UnsuspendOrRemoveRequest req = new UnsuspendOrRemoveRequest();
      req.setEntries(unrevokeEntries);
      req.setIssuer(new X500NameType(issuer));
      req.setAuthorityKeyIdentifier(aki);
      UnSuspendOrRemoveCertsResponse resp = sdk.unsuspendCerts(caName, req);
      respEntries = resp.getEntries();
    }

    GeneralName caGn = new GeneralName(issuer);
    RevRepContentBuilder repContentBuilder = new RevRepContentBuilder();
    for (SingleCertSerialEntry m : respEntries) {
      ErrorEntry error = m.getError();

      PKIStatusInfo status;
      if (error == null) {
        status = new PKIStatusInfo(granted);
      } else {
        status = buildPKIStatusInfo(error.getCode(), error.getMessage());
      }

      BigInteger sn = m.getSerialNumber();
      repContentBuilder.add(status, new CertId(caGn, sn));
    }

    return new PKIBody(PKIBody.TYPE_REVOCATION_REP, repContentBuilder.build());
  } // method revokeOrUnrevokeOrRemoveCertificates

  @Override
  protected PKIBody confirmCertificates(
      String caName, ASN1OctetString transactionId, CertConfirmContent certConf)
      throws SdkErrorResponseException {
    CertStatus[] certStatuses = certConf.toCertStatusArray();

    List<ConfirmCertRequestEntry> entries = new LinkedList<>();

    for (CertStatus certStatus : certStatuses) {
      ConfirmCertRequestEntry entry = new ConfirmCertRequestEntry();
      entry.setCertReqId(certStatus.getCertReqId().getValue());
      entry.setCerthash(certStatus.getCertHash().getOctets());

      PKIStatusInfo statusInfo = certStatus.getStatusInfo();
      boolean accept = true;
      if (statusInfo != null) {
        int status = statusInfo.getStatus().intValue();
        if (GRANTED != status && GRANTED_WITH_MODS != status) {
          accept = false;
        }
      }
      entry.setAccept(accept);

      entries.add(entry);
    }

    ConfirmCertsRequest sdkReq = new ConfirmCertsRequest();
    sdkReq.setTransactionId(Hex.encode(transactionId.getOctets()));
    sdkReq.setEntries(entries);

    try {
      sdk.confirmCerts(caName, sdkReq);
      return new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
    } catch (IOException e) {
      return new PKIBody(PKIBody.TYPE_ERROR,
          new ErrorMsgContent(new PKIStatusInfo(
              rejection, null, new PKIFailureInfo(systemFailure))));
    }
  } // method confirmCertificates

  @Override
  protected PKIBody revokePendingCertificates(
      String caName, ASN1OctetString transactionId)
      throws SdkErrorResponseException {
    try {
      sdk.revokePendingCerts(caName, Hex.encode(transactionId.getOctets()));
      return new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
    } catch (IOException e) {
      return new PKIBody(PKIBody.TYPE_ERROR,
          new ErrorMsgContent(new PKIStatusInfo(
              rejection, null, new PKIFailureInfo(systemFailure))));
    }
  } // method revokePendingCertificates

  @Override
  protected PKIBody cmpEnrollCert(
      String caName, String dfltCertprofileName, boolean groupEnroll,
      PKIMessage request, PKIHeaderBuilder respHeader, PKIHeader reqHeader, PKIBody reqBody,
      Requestor requestor, ASN1OctetString tid, AuditEvent event)
      throws InsufficientPermissionException, SdkErrorResponseException {
    if (dfltCertprofileName != null) {
      dfltCertprofileName = dfltCertprofileName.toLowerCase(Locale.ROOT);
    }

    long confirmWaitTime = cmpControl.getConfirmWaitTime();
    if (confirmWaitTime < 0) {
      confirmWaitTime *= -1;
    }
    confirmWaitTime *= 1000; // second to millisecond

    PKIBody respBody;

    int type = reqBody.getType();
    try {
      if (type == PKIBody.TYPE_INIT_REQ) {
        checkPermission(requestor, PermissionConstants.ENROLL_CERT);
        CertReqMessages cr = CertReqMessages.getInstance(reqBody.getContent());
        CertRepMessage repMessage = processCertReqMessages(caName, dfltCertprofileName, groupEnroll,
            request, requestor, tid, cr, event);
        respBody = new PKIBody(PKIBody.TYPE_INIT_REP, repMessage);
      } else if (type == PKIBody.TYPE_CERT_REQ) {
        checkPermission(requestor, PermissionConstants.ENROLL_CERT);
        CertReqMessages cr = CertReqMessages.getInstance(reqBody.getContent());
        CertRepMessage repMessage = processCertReqMessages(
            caName, dfltCertprofileName, groupEnroll, request, requestor, tid, cr, event);
        respBody = new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
      } else if (type == PKIBody.TYPE_KEY_UPDATE_REQ) {
        checkPermission(requestor, PermissionConstants.KEY_UPDATE);
        CertReqMessages kur = CertReqMessages.getInstance(reqBody.getContent());
        CertRepMessage repMessage = processCertReqMessages(
            caName, dfltCertprofileName, groupEnroll, request, requestor, tid, kur, event);
        respBody = new PKIBody(PKIBody.TYPE_KEY_UPDATE_REP, repMessage);
      } else if (type == PKIBody.TYPE_P10_CERT_REQ) {
        checkPermission(requestor, PermissionConstants.ENROLL_CERT);
        respBody = processP10cr(
            caName, dfltCertprofileName, requestor, tid, reqHeader,
            CertificationRequest.getInstance(reqBody.getContent()), event);
      } else if (type == PKIBody.TYPE_CROSS_CERT_REQ) {
        checkPermission(requestor, PermissionConstants.ENROLL_CROSS);
        CertReqMessages cr = CertReqMessages.getInstance(reqBody.getContent());
        CertRepMessage repMessage = processCertReqMessages(caName, dfltCertprofileName, groupEnroll,
            request, requestor, tid, cr, event);
        respBody = new PKIBody(PKIBody.TYPE_CROSS_CERT_REP, repMessage);
      } else {
        throw new IllegalStateException("should not reach here");
      } // switch type
    } catch (IOException e) {
      LogUtil.error(LOG, e);
      return buildErrorMsgPkiBody(rejection, systemFailure, null);
    }

    // TODO: evaluate the confirm and confirmTime of the response
    InfoTypeAndValue tv;
    if (!cmpControl.isConfirmCert() && CmpUtil.isImplicitConfirm(reqHeader)) {
      tv = CmpUtil.getImplicitConfirmGeneralInfo();
    } else {
      Date now = new Date();
      respHeader.setMessageTime(new ASN1GeneralizedTime(now));
      tv = new InfoTypeAndValue(CMPObjectIdentifiers.it_confirmWaitTime,
          new ASN1GeneralizedTime(new Date(System.currentTimeMillis() + confirmWaitTime)));
    }

    respHeader.setGeneralInfo(tv);
    return respBody;
  } // method cmpEnrollCert

  @Override
  protected PKIBody cmpUnRevokeCertificates(
      String caName, PKIMessage request, PKIHeaderBuilder respHeader, PKIHeader reqHeader,
      PKIBody reqBody, Requestor requestor, AuditEvent event)
      throws SdkErrorResponseException {
    Integer requiredPermission = null;
    boolean allRevdetailsOfSameType = true;

    RevReqContent rr = RevReqContent.getInstance(reqBody.getContent());
    RevDetails[] revContent = rr.toRevDetailsArray();

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
          requiredPermission = PermissionConstants.UNSUSPEND_CERT;
        } else if (requiredPermission != PermissionConstants.UNSUSPEND_CERT) {
          allRevdetailsOfSameType = false;
          break;
        }
      } else {
        if (requiredPermission == null) {
          event.addEventType(TYPE_rr_revoke);
          requiredPermission = PermissionConstants.REVOKE_CERT;
        } else if (requiredPermission != PermissionConstants.REVOKE_CERT) {
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

    boolean revoke = requiredPermission == PermissionConstants.REVOKE_CERT;
    try {
      return unRevokeCertificates(caName, rr, revoke, event);
    } catch (IOException e) {
      LogUtil.error(LOG, e);
      return buildErrorMsgPkiBody(rejection, systemFailure, null);
    }
  } // method cmpUnRevokeCertificates

}
