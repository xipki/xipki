// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.pkix.asn1.cmp.*;
import org.xipki.pkix.asn1.crmf.CertId;
import org.xipki.pkix.asn1.crmf.CertReqMessages;
import org.xipki.pkix.asn1.crmf.CertReqMsg;
import org.xipki.pkix.asn1.crmf.CertTemplate;
import org.xipki.pkix.asn1.crmf.OptionalValidity;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.CmpOIDs;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.pkix.asn1.pkcs10.CertificationRequest;
import org.xipki.pkix.asn1.x500.AttributeTypeAndValue;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.AuthorityKeyIdentifier;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.asn1.x509.Extensions;
import org.xipki.pkix.asn1.x509.GeneralName;
import org.xipki.ca.gateway.CaNameSigners;
import org.xipki.ca.gateway.GatewayUtil;
import org.xipki.ca.gateway.PopControl;
import org.xipki.ca.sdk.*;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.pkix.cmp.CertificateRequestMessage;
import org.xipki.pkix.SecurityFactory;
import org.xipki.pkix.auth.Requestor;
import org.xipki.pkix.auth.RequestorAuthenticator;
import org.xipki.pkix.cmp.CmpUtf8Pairs;
import org.xipki.pkix.cmp.CmpUtil;
import org.xipki.pkix.exception.ErrorCode;
import org.xipki.pkix.exception.OperationException;
import org.xipki.pkix.cert.CrlReason;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.audit.AuditEvent;
import org.xipki.util.audit.AuditStatus;
import org.xipki.codec.exception.InsufficientPermissionException;
import org.xipki.util.misc.DateUtil;
import org.xipki.pkix.util.misc.LogUtil;
import org.xipki.pkix.util.misc.StringUtil;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.xipki.pkix.asn1.cmp.PKIFailureInfo.badCertId;
import static org.xipki.pkix.asn1.cmp.PKIFailureInfo.badCertTemplate;
import static org.xipki.pkix.asn1.cmp.PKIFailureInfo.badPOP;
import static org.xipki.pkix.asn1.cmp.PKIFailureInfo.badRequest;
import static org.xipki.pkix.asn1.cmp.PKIFailureInfo.notAuthorized;
import static org.xipki.pkix.asn1.cmp.PKIFailureInfo.systemFailure;
import static org.xipki.pkix.asn1.cmp.PKIStatus.accepted;
import static org.xipki.pkix.asn1.cmp.PKIStatus.grantedWithMods;
import static org.xipki.pkix.asn1.cmp.PKIStatus.rejection;
import static org.xipki.pkix.asn1.cmp.PKIStatus.waiting;

/**
 * CMP Responder.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpResponder extends BaseCmpResponder {

  private static final Logger LOG = LoggerFactory.getLogger(CmpResponder.class);

  public CmpResponder(
      CmpControl cmpControl, SdkClient sdk, SecurityFactory securityFactory,
      CaNameSigners signers, RequestorAuthenticator authenticator, PopControl popControl)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    super(cmpControl, sdk, securityFactory, signers, authenticator, popControl);
  }

  private CertRepMessage processCertReqMessages(
      CmpVersion cmpVersion, String caName, String dfltCertprofileName,
      boolean groupEnroll, PKIMessage request, Requestor requestor,
      Asn1OctetString tid, CertReqMessages cr, AuditEvent event)
      throws InsufficientPermissionException, CodecException, SdkErrorResponseException {
    final int n = cr.size();

    boolean reenroll = request.getBody().getTagNo() == PKIBody.tag_kur;
    String[] certprofileNames = CmpUtil.extractCertProfile(
        request.getHeader().getGeneralInfo());

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

    // more cert profile names than allowed
    if (numCertprofileNames > n ||
        // cert profile names specified are not enough
        (!reenroll && withNullProfileNames)) {
      CertResponse[] certResps = new CertResponse[n];
      for (int i = 0; i < n; i++) {
        certResps[i] = new CertResponse(cr.get(i).getCertReq().getCertReqId(),
            generateRejectionStatus(badCertTemplate,
                "number of specified cert profile names is not correct"));
      }

      event.setStatus(AuditStatus.FAILED);
      return new CertRepMessage(null, new CertResponse.Seq0(certResps));
    }

    List<EnrollCertsRequest.Entry> certTemplateDatas = new ArrayList<>(n);

    Map<Integer, CertResponse> failureResps = new HashMap<>();

    // pre-process requests
    for (int i = 0; i < n; i++) {
      CertReqMsg reqMsg = cr.get(i);
      Asn1Integer certReqId = reqMsg.getCertReq().getCertReqId();
      CertificateRequestMessage req = new CertificateRequestMessage(reqMsg);
      CertTemplate certTemp = req.getCertTemplate();

      SubjectPublicKeyInfo publicKey = certTemp.getPublicKey();
      X500Name subject = certTemp.getSubject();

      OptionalValidity validity = certTemp.getValidity();

      Instant notBefore = null;
      Instant notAfter = null;
      if (validity != null) {
        if (validity.getNotBefore() != null) {
          notBefore = validity.notBefore();
        }
        if (validity.getNotAfter() != null) {
          notAfter = validity.notAfter();
        }
      }

      OldCertInfo oldCertInfo = null;

      if (reenroll) {
        AttributeTypeAndValue.Seq1 controls = reqMsg.getCertReq().getControls();
        AttributeTypeAndValue oldCertIdAtv = null;
        if (controls != null) {
          for (AttributeTypeAndValue atv : controls) {
            if (atv.getType().equals(CmpOIDs.id_regCtrl_oldCertID)) {
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

        CertId oldCertId = CertId.fromAsn1(oldCertIdAtv.getValue().asSequence());
        if (GeneralName.tag_directoryName != oldCertId.getIssuer().getTagNo()) {
          addErrCertResp(failureResps, i, certReqId, badCertId, "invalid regCtrl oldCertID");
          continue;
        }

        boolean reuseOldPublicKey = publicKey == null;
        oldCertInfo = new OldCertInfo(reuseOldPublicKey, new OldCertInfo.ByIssuerAndSerial(
                new X500NameType(oldCertId.getIssuer().getDirectoryName()),
                oldCertId.serialNumber()));
      } // end if(reenroll)

      String certprofileName = certprofileNames[i];
      if (StringUtil.isNotBlank(certprofileName)) {
        if (!requestor.isCertprofilePermitted(caName, certprofileName)) {
          addErrCertResp(failureResps, i, certReqId, notAuthorized,
              "certprofile " + certprofileName + " is not allowed");
          continue;
        }
      } else if (!requestor.isAllCertprofilesPermitted(caName)) {
        // the CA may use any certprofile, e.g. that of the old certificate.
        addErrCertResp(failureResps, i, certReqId, notAuthorized,
            "certprofile is not specified, and not all certprofiles are allowed");
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

      template.extensions(certTemp.getExtensions());

      if (publicKey != null) {
        template.setSubjectPublicKey(publicKey.getEncoded());
      }

      if (subject != null) {
        template.setSubject(new X500NameType(subject));
      }

      if (oldCertInfo != null) {
        template.setOldCertInfo(oldCertInfo);
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
          certResps[i] = new CertResponse(cr.get(i).getCertReq().getCertReqId(),
              generateRejectionStatus(badRequest,
                  "failure in the parallel entries in the same request"));
        }
      }
      return new CertRepMessage(null, new CertResponse.Seq0(certResps));
    }

    boolean cross = request.getBody().getTagNo() == PKIBody.tag_ccr;
    return enrollCerts(caName, groupEnroll, reenroll, cross, requestor, cmpVersion, tid,
        certTemplateDatas.toArray(new EnrollCertsRequest.Entry[0]), event);
  } // method processCertReqMessages

  /**
   * handle the PKI body with the choice {@code p10cr}<br/>
   * Since it is not possible to add attribute to the PKCS#10 request (CSR),
   * the certificate profile must be specified in the attribute
   * regInfo-utf8Pairs (1.3.6.1.5.5.7.5.2.1) within PKIHeader.generalInfo
   */
  private PKIBody processP10cr(
      CmpVersion cmpVersion, String caName, String dfltCertprofileName,
      Requestor requestor, Asn1OctetString tid, PKIHeader reqHeader,
      CertificationRequest p10cr, AuditEvent event) throws SdkErrorResponseException {
    // verify the POP first
    CertRepMessage certResp = null;
    Asn1Integer certReqId = new Asn1Integer(BigInteger.valueOf(-1));

    if (!GatewayUtil.verifyCsr(p10cr, securityFactory, popControl)) {
      LOG.warn("could not validate POP for the pkcs#10 request");
      certResp = buildErrCertResp(certReqId, badPOP, "invalid POP");
    } else {
      String certprofileName = null;
      Instant notBefore = null;
      Instant notAfter = null;

      try {
        InfoTypeAndValue.Seq1 generalInfo = reqHeader.getGeneralInfo();
        CmpUtf8Pairs keyvalues = CmpUtil.extractUtf8Pairs(generalInfo);

        // CertProfile name
        String[] list = CmpUtil.extractCertProfile(generalInfo);
        if (list != null && list.length > 0) {
          certprofileName = list[0];
        }

        // NotBefore and NotAfter
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
      } catch (CodecException ex) {
        LOG.warn("could not parse the GeneralInfo in the request's CMP Header");
        certResp = buildErrCertResp(certReqId, badPOP, "invalid CMP Header");
      }

      if (certResp == null) {
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
            certTemplate.setP10req(p10cr.getEncoded());

            try {
              certResp = enrollCerts(caName, false, false, false,
                  requestor, cmpVersion, tid, new EnrollCertsRequest.Entry[]{certTemplate}, event);
            } catch (CodecException e) {
              LogUtil.error(LOG, e);
              return buildErrorMsgPkiBody(rejection, systemFailure, null);
            }
          }
        }
      }
    }

    if (event.status() == null || event.status() != AuditStatus.FAILED) {
      PKIStatusInfo statusObj = certResp.getResponse().get(0).getStatus();
      int status = statusObj.getStatus().value();
      if (status != accepted.value() && status != grantedWithMods.value()
          && status != waiting.value()) {
        event.setStatus(AuditStatus.FAILED);
        PKIFreeText statusStr = statusObj.getStatusString();
        if (statusStr != null) {
          event.addEventData(CaAuditConstants.NAME_message, statusStr.getStringAt(0));
        }
      }
    }

    return PKIBody.ofCp(certResp);
  } // method processP10cr

  private CertRepMessage enrollCerts(
      String caName, boolean groupEnroll, boolean reenroll, boolean cross,
      Requestor requestor, CmpVersion cmpVersion, Asn1OctetString tid,
      EnrollCertsRequest.Entry[] templates, AuditEvent event)
      throws CodecException, SdkErrorResponseException {
    String hexTid = Hex.encode(tid.getOctets());

    EnrollCertsRequest sdkReq = new EnrollCertsRequest();
    sdkReq.setExplicitConfirm(cmpControl.isConfirmCert());
    sdkReq.setGroupEnroll(groupEnroll);
    sdkReq.setConfirmWaitTimeMs((int) cmpControl.confirmWaitTime().toMillis());
    sdkReq.setCaCertMode(cmpControl.caCertsMode());
    sdkReq.setTransactionId(hexTid);
    sdkReq.setEntries(templates);

    for (EnrollCertsRequest.Entry m : templates) {
      event.addEventData(CaAuditConstants.NAME_certprofile, m.certprofile());
      X500Name subject = null;
      if (m.subject() != null) {
        subject = m.subject().toX500Name();
      } else if (m.p10req() != null) {
        CertificationRequest csr;
        try {
          csr = GatewayUtil.parseCsrInRequest(m.p10req());
        } catch (OperationException e) {
          throw new SdkErrorResponseException(ErrorCode.BAD_REQUEST,
              "error parsing PKCS#10 request");
        }
        subject = csr.getSubject();
      }
      if (subject != null) {
        event.addEventData(CaAuditConstants.NAME_req_subject,
            "\"" + X509Util.x500NameText(subject) + "\"");
      }
    }

    EnrollOrPollCertsResponse resp;
    if (cross) {
      resp = sdk.enrollCrossCerts(caName, sdkReq);
    } else {
      resp = reenroll ? sdk.reenrollCerts(caName, sdkReq) : sdk.enrollCerts(caName, sdkReq);
    }

    EnrollOrPollCertsResponse.Entry[] rentries = resp.entries();
    CertResponse[] certResponses = new CertResponse[rentries.length];
    EphemeralKeyPair ephemeralKeyPair = new EphemeralKeyPair();
    for (int i = 0; i < rentries.length; i++) {
      EnrollOrPollCertsResponse.Entry respEntry = rentries[i];
      ErrorEntry error = respEntry.error();
      if (error != null) {
        certResponses[i] = new CertResponse(new Asn1Integer(respEntry.id()),
            buildPKIStatusInfo(error.code(), error.message()));
      } else {
        certResponses[i] = postProcessCertInfo(
            cmpVersion, new Asn1Integer(respEntry.id()), requestor,
            respEntry.cert(), respEntry.privateKey(), ephemeralKeyPair);
      }
    }

    CMPCertificate[] caPubs = null;
    byte[][] extraCerts = resp.extraCerts();
    if (extraCerts != null && extraCerts.length > 0) {
      caPubs = new CMPCertificate[extraCerts.length];
      for (int i = 0; i < extraCerts.length; i++) {
        caPubs[i] = CMPCertificate.ofX509v3PKCert(Certificate.fromEncoded(extraCerts[i]));
      }
    }

    return new CertRepMessage(caPubs == null ? null : new CMPCertificate.Seq1(caPubs),
        new CertResponse.Seq0(certResponses));
  }

  private PKIBody unRevokeCertificates(RevReqContent rr, boolean revoke, AuditEvent event)
      throws SdkErrorResponseException {
    if (rr.isEmpty()) {
      return buildErrorMsgPkiBody(rejection, badRequest, "no entry is specified");
    }

    List<RevokeCertsRequest.Entry> revokeEntries = revoke
        ? new ArrayList<>(rr.size()) : null;
    List<BigInteger> unrevokeEntries = revoke ? null : new ArrayList<>(rr.size());
    X500Name issuer = null;
    byte[] aki = null;

    for (RevDetails revDetails : rr) {
      CertTemplate certDetails = revDetails.getCertDetails();
      X500Name tIssuer = certDetails.getIssuer();
      if (tIssuer == null) {
        return buildErrorMsgPkiBody(rejection, badCertTemplate, "issuer is not present");
      }

      if (issuer == null) {
        issuer = tIssuer;
      } else if (!issuer.equals(tIssuer)) {
        return buildErrorMsgPkiBody(rejection, badCertTemplate,
            "not all issuers are of the same");
      }

      if (certDetails.getSerialNumber() == null) {
        return buildErrorMsgPkiBody(rejection, badCertTemplate, "serialNumber is not present");
      }

      BigInteger serialNumber = certDetails.serialNumber();

      /*
      CertTemplate ::= SEQUENCE {
      version      [0] Version               OPTIONAL,
      serialNumber [1] INTEGER               OPTIONAL,
      signingAlg   [2] AlgorithmIdentifier   OPTIONAL, -
      issuer       [3] Name                  OPTIONAL,
      validity     [4] OptionalValidity      OPTIONAL, -
      subject      [5] Name                  OPTIONAL, -
      publicKey    [6] SubjectPublicKeyInfo  OPTIONAL, -
      issuerUID    [7] UniqueIdentifier      OPTIONAL, -
      subjectUID   [8] UniqueIdentifier      OPTIONAL, -
      extensions   [9] Extensions            OPTIONAL }
       */
      if (  certDetails.getSigningAlg() != null || certDetails.getValidity() != null
          ||   certDetails.getSubject() != null || certDetails.getPublicKey() != null
          || certDetails.getIssuerUID() != null || certDetails.getSubjectUID() != null) {
        return buildErrorMsgPkiBody(rejection, badCertTemplate,
            "only version, issuer and serialNumber in " +
            "RevDetails.certDetails are allowed, but more is specified");
      }

      // authorityKeyIdentifier
      if (certDetails.getExtensions() != null) {
        Extensions exts = certDetails.getExtensions();
        Set<Asn1Oid> oids = exts.getCriticalExtensionIds();
        if (oids != null) {
          for (Asn1Oid oid : oids) {
            if (!ExtensionOIDs.authorityKeyIdentifier.equals(oid)) {
              return buildErrorMsgPkiBody(rejection, badCertTemplate,
                  "unknown critical extension " + oid.getId());
            }
          }
        }

        Extension ext = exts.getExtension(ExtensionOIDs.authorityKeyIdentifier);
        if (ext != null) {
          AuthorityKeyIdentifier tAki = ext.getAuthorityKeyIdentifier();
          if (tAki.getKeyIdentifierOctets() == null) {
            return buildErrorMsgPkiBody(rejection, badCertTemplate, "issuer's AKI not present");
          }

          if (aki == null) {
            aki = tAki.getKeyIdentifierOctets();
          } else if (!Arrays.equals(aki, tAki.getKeyIdentifierOctets())) {
            return buildErrorMsgPkiBody(rejection, badCertTemplate,
                "not all AKIs are of the same");
          }
        }
      }

      if (revoke) {
        Instant invalidityDate = null;
        CrlReason reason = null;

        Extensions crlDetails = revDetails.getCrlEntryDetails();
        if (crlDetails != null) {
          Extension extn = crlDetails.getExtension(ExtensionOIDs.reasonCode);
          if (extn != null) {
            reason = CrlReason.forReason(extn.getReasonCode());
          }

          extn = crlDetails.getExtension(ExtensionOIDs.invalidityDate);
          if (extn != null) {
            invalidityDate = extn.invalidityDate();
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
      RevokeCertsRequest req = new RevokeCertsRequest(null, issuerType, aki,
          revokeEntries.toArray(new RevokeCertsRequest.Entry[0]));
      RevokeCertsResponse resp = sdk.revokeCerts(req);
      respEntries = resp.entries();
    } else {
      UnsuspendOrRemoveCertsRequest req = new UnsuspendOrRemoveCertsRequest(
          null, issuerType, aki, unrevokeEntries.toArray(new BigInteger[0]));
      UnSuspendOrRemoveCertsResponse resp = sdk.unsuspendCerts(req);
      respEntries = resp.entries();
    }

    GeneralName caGn = GeneralName.ofDirectoryName(issuer);
    RevRepContent.Builder repContentBuilder = new RevRepContent.Builder();
    for (SingleCertSerialEntry m : respEntries) {
      ErrorEntry error = m.error();

      PKIStatusInfo status = error == null ? new PKIStatusInfo(accepted)
          : buildPKIStatusInfo(error.code(), error.message());

      repContentBuilder.add(status, new CertId(caGn, m.serialNumber()));
    }

    return PKIBody.ofRp(repContentBuilder.build());
  } // method unRevokeCertificates

  @Override
  protected PKIBody confirmCertificates(
      String caName, Asn1OctetString transactionId, CertConfirmContent certConf)
      throws SdkErrorResponseException {
    ConfirmCertsRequest.Entry[] entries = new ConfirmCertsRequest.Entry[certConf.size()];

    for (int i = 0; i < entries.length; i++) {
      CmpCertStatus certStatus = certConf.get(i);
      PKIStatusInfo statusInfo = certStatus.getStatusInfo();
      boolean accept = true;
      if (statusInfo != null) {
        PKIStatus status = statusInfo.getStatus();
        if (!accepted.equals(status) && !grantedWithMods.equals(status)) {
          accept = false;
        }
      }

      entries[i] = new ConfirmCertsRequest.Entry(accept,
          certStatus.certReqId(), certStatus.certHash());
    }

    ConfirmCertsRequest sdkReq =
        new ConfirmCertsRequest(Hex.encode(transactionId.getOctets()), entries);

    sdk.confirmCerts(caName, sdkReq);
    return PKIBody.ofPkiconf();
  } // method confirmCertificates

  @Override
  protected PKIBody revokePendingCertificates(String caName, Asn1OctetString transactionId)
      throws SdkErrorResponseException {
    sdk.revokePendingCerts(caName, Hex.encode(transactionId.getOctets()));
    return PKIBody.ofPkiconf();
  }

  @Override
  protected PKIBody cmpEnrollCert(
      CmpVersion cmpVersion, String caName, String dfltCertprofileName,
      boolean groupEnroll, PKIMessage request, PKIHeader respHeader,
      PKIHeader reqHeader, PKIBody reqBody, Requestor requestor, Asn1OctetString tid,
      AuditEvent event) throws InsufficientPermissionException, SdkErrorResponseException {
    if (dfltCertprofileName != null) {
      dfltCertprofileName = dfltCertprofileName.toLowerCase(Locale.ROOT);
    }

    Duration confirmWaitTime = cmpControl.confirmWaitTime();

    PKIBody respBody;

    int type = reqBody.getTagNo();
    try {
      switch (type) {
        case PKIBody.tag_ir: {
          checkPermission(requestor, Requestor.Permission.ENROLL_CERT);
          CertReqMessages cr = reqBody.getIr();

          CertRepMessage repMessage = processCertReqMessages(cmpVersion, caName,
              dfltCertprofileName, groupEnroll, request, requestor, tid, cr, event);

          respBody = PKIBody.ofIp(repMessage);
          break;
        }
        case PKIBody.tag_cr: {
          checkPermission(requestor, Requestor.Permission.ENROLL_CERT);
          CertReqMessages cr = reqBody.getCr();

          CertRepMessage repMessage = processCertReqMessages(cmpVersion, caName,
              dfltCertprofileName, groupEnroll, request, requestor, tid, cr, event);

          respBody = PKIBody.ofCp(repMessage);
          break;
        }
        case PKIBody.tag_kur: {
          checkPermission(requestor, Requestor.Permission.REENROLL_CERT);
          CertReqMessages kur = reqBody.getKur();

          CertRepMessage repMessage = processCertReqMessages(cmpVersion, caName,
              dfltCertprofileName, groupEnroll, request, requestor, tid, kur, event);

          respBody = PKIBody.ofKup(repMessage);
          break;
        }
        case PKIBody.tag_p10cr: {
          checkPermission(requestor, Requestor.Permission.ENROLL_CERT);
          respBody = processP10cr(cmpVersion, caName, dfltCertprofileName, requestor,
              tid, reqHeader, reqBody.getP10cr(), event);
          break;
        }
        case PKIBody.tag_ccr: {
          checkPermission(requestor, Requestor.Permission.ENROLL_CROSS);

          CertReqMessages cr = reqBody.getCcr();

          CertRepMessage repMessage = processCertReqMessages(cmpVersion, caName,
              dfltCertprofileName, groupEnroll, request, requestor, tid, cr, event);

          respBody = PKIBody.ofCcp(repMessage);
          break;
        }
        default:
          throw new IllegalStateException("should not reach here");
      } // switch type
    } catch (CodecException e) {
      LogUtil.error(LOG, e);
      return buildErrorMsgPkiBody(rejection, systemFailure, null);
    }

    // TODO: evaluate the confirm and confirmTime of the response
    InfoTypeAndValue tv;
    if (!cmpControl.isConfirmCert() && CmpUtil.isImplicitConfirm(reqHeader)) {
      tv = CmpUtil.getImplicitConfirmGeneralInfo();
    } else {
      Instant now = Instant.now();
      respHeader.setMessageTime(new Asn1GeneralizedTime(now));
      tv = new InfoTypeAndValue(CmpOIDs.it_confirmWaitTime,
          new Asn1GeneralizedTime((Instant) confirmWaitTime.addTo(now)));
    }

    respHeader.setGeneralInfo(new InfoTypeAndValue.Seq1(tv));
    return respBody;
  } // method cmpEnrollCert

  @Override
  protected PKIBody cmpUnRevokeCertificates(
      String caName, PKIMessage request, PKIHeader respHeader,
      PKIHeader reqHeader, PKIBody reqBody, Requestor requestor, AuditEvent event)
      throws SdkErrorResponseException {
    RevReqContent rr = reqBody.getRr();
    if (rr.isEmpty()) {
      return buildErrorMsgPkiBody(rejection, badRequest, "no entry is specified");
    }

    Requestor.Permission requiredPermission = null;
    boolean allRevdetailsOfSameType = true;

    for (RevDetails revDetails : rr) {
      Extensions crlDetails = revDetails.getCrlEntryDetails();
      int reasonCode = CrlReason.UNSPECIFIED.code();
      if (crlDetails != null) {
        Extension extn = crlDetails.getExtension(ExtensionOIDs.reasonCode);
        if (extn != null) {
          reasonCode = extn.getReasonCode().getValue();
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

      if (reasonCode == CrlReason.REMOVE_FROM_CRL.code()) {
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
          badRequest));

      return PKIBody.ofError(emc);
    }

    try {
      checkPermission(requestor, requiredPermission);
    } catch (InsufficientPermissionException ex) {
      event.setStatus(AuditStatus.FAILED);
      event.addEventData(CaAuditConstants.NAME_message, "NOT_PERMITTED");
      return buildErrorMsgPkiBody(rejection, notAuthorized, null);
    }

    boolean revoke = requiredPermission == Requestor.Permission.REVOKE_CERT;
    return unRevokeCertificates(rr, revoke, event);
  } // method cmpUnRevokeCertificates

}
