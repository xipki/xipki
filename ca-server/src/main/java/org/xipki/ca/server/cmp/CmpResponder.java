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

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.api.*;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.api.mgmt.CmpControl;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.RequestorInfo.CmpRequestorInfo;
import org.xipki.ca.server.CaAuditConstants;
import org.xipki.ca.server.CaUtil;
import org.xipki.ca.server.CertTemplateData;
import org.xipki.ca.server.X509Ca;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.CrlReason;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityConstants;
import org.xipki.security.cmp.CmpUtf8Pairs;
import org.xipki.security.cmp.CmpUtil;
import org.xipki.util.CollectionUtil;
import org.xipki.util.DateUtil;
import org.xipki.util.Hex;
import org.xipki.util.LogUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.bouncycastle.asn1.cmp.PKIFailureInfo.*;
import static org.bouncycastle.asn1.cmp.PKIStatus.*;

/**
 * CMP responder.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpResponder extends BaseCmpResponder {

  private static final Logger LOG = LoggerFactory.getLogger(BaseCmpResponder.class);

  /**
   * Used by XiPKI CA till 5.3.13.
   */
  @Deprecated
  private static final String KEY_CERTPROFILE = "certprofile";

  private class PendingPoolCleaner implements Runnable {

    @Override
    public void run() {
      Set<CertificateInfo> remainingCerts = pendingCertPool.removeConfirmTimeoutedCertificates();
      if (CollectionUtil.isEmpty(remainingCerts)) {
        return;
      }

      Date invalidityDate = new Date();
      X509Ca ca = getCa();
      for (CertificateInfo remainingCert : remainingCerts) {
        BigInteger serialNumber = remainingCert.getCert().getCert().getSerialNumber();
        try {
          ca.revokeCert(serialNumber, CrlReason.CESSATION_OF_OPERATION,
              invalidityDate, CaAuditConstants.MSGID_ca_routine);
        } catch (Throwable th) {
          LOG.error("could not revoke certificate (CA={}, serialNumber={}): {}",
              ca.getCaInfo().getIdent(), LogUtil.formatCsn(serialNumber), th.getMessage());
        }
      }
    } // method run

  } // class PendingPoolCleaner

  private final PendingCertificatePool pendingCertPool;

  public CmpResponder(CaManagerImpl caManager, String caName) throws NoSuchAlgorithmException {
    super(caManager, caName);

    this.pendingCertPool = new PendingCertificatePool();
    caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(
        new PendingPoolCleaner(), 10, 10, TimeUnit.MINUTES);
  }

  private CertRepMessage processCertReqMessages(String dfltCertprofileName,
      PKIMessage request, CmpRequestorInfo requestor, ASN1OctetString tid,
      CertReqMessages cr, boolean allowKeyGen, CmpControl cmpControl,
      String msgId, AuditEvent event) throws InsufficientPermissionException {
    CertReqMsg[] certReqMsgs = cr.toCertReqMsgArray();
    final int n = certReqMsgs.length;

    List<CertResponse> resps = new ArrayList<>(1);

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
    if (!kup && (numCertprofileNames != n)) {
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

    List<CertTemplateData> certTemplateDatas = new ArrayList<>(n);

    // pre-process requests
    for (int i = 0; i < n; i++) {
      if (cmpControl.isGroupEnroll() && certTemplateDatas.size() != i) {
        // last certReqMsg cannot be used to enroll certificate
        break;
      }

      CertReqMsg reqMsg = certReqMsgs[i];
      ASN1Integer certReqId = reqMsg.getCertReq().getCertReqId();
      CertificateRequestMessage req = new CertificateRequestMessage(reqMsg);
      CertTemplate certTemp = req.getCertTemplate();

      SubjectPublicKeyInfo publicKey = certTemp.getPublicKey();
      X500Name subject = certTemp.getSubject();
      Extensions extensions = certTemp.getExtensions();

      // till version 5.3.13, UTF8Pairs is used to specify the CertProfile
      CmpUtf8Pairs utf8Pairs = CmpUtil.extractUtf8Pairs(reqMsg.getRegInfo());
      String certprofileName = null;
      if (utf8Pairs != null) {
        certprofileName = utf8Pairs.value(CmpUtf8Pairs.KEY_NOTAFTER);
      }

      if (certprofileName == null && certprofileNames != null) {
        certprofileName = certprofileNames[i];
      }

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
            addErrCertResp(resps, certReqId, systemFailure, "could not parse the controls");
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
          addErrCertResp(resps, certReqId, badCertTemplate, "no getCtrl oldCertID is specified");
          continue;
        }

        CertId oldCertId = CertId.getInstance(oldCertIdAtv.getValue());

        if (GeneralName.directoryName != oldCertId.getIssuer().getTagNo()) {
          addErrCertResp(resps, certReqId, badCertId, "invalid regCtrl oldCertID");
          continue;
        }

        X500Name issuer = X500Name.getInstance(oldCertId.getIssuer().getName());
        BigInteger serialNumber = oldCertId.getSerialNumber().getValue();
        CertWithRevocationInfo oldCert;
        try {
          oldCert = caManager.getCert(issuer, serialNumber);
        } catch (CaMgmtException ex) {
          addErrCertResp(resps, certReqId, systemFailure, "error while finding certificate with "
              + "the issuer " + issuer + "and serial number " + serialNumber);
          continue;
        }

        if (oldCert == null) {
          addErrCertResp(resps, certReqId, badCertId, "found no certificate with the issuer "
              + issuer + "and serial number " + serialNumber);
          continue;
        }

        if (oldCert.isRevoked()) {
          addErrCertResp(resps, certReqId, certRevoked, "could not update a revoked certificate "
              + "with the issuer " + issuer + "and serial number " + serialNumber);
          continue;
        }

        if (certprofileName == null) {
          certprofileName = oldCert.getCertprofile();
        }

        if (subject == null) {
          subject = oldCert.getCert().getCert().getSubject();
        }

        // extensions
        Map<String, Extension> extns = new HashMap<>();
        if (extensions != null) {
          // add all requested extensions
          ASN1ObjectIdentifier[] oids = extensions.getExtensionOIDs();
          for (ASN1ObjectIdentifier oid : oids) {
            extns.put(oid.getId(), extensions.getExtension(oid));
          }
        }

        // extract extensions from the certificate
        Extensions oldExtensions = oldCert.getCert().getCert().toBcCert().getExtensions();
        ASN1ObjectIdentifier[] oldOids = oldExtensions.getExtensionOIDs();
        for (ASN1ObjectIdentifier oid : oldOids) {
          String id = oid.getId();
          if (!(extns.containsKey(id) || kupCertExtnIds.contains(id))) {
            extns.put(id, oldExtensions.getExtension(oid));
          }
        }

        extensions = new Extensions(extns.values().toArray(new Extension[0]));
      }

      if (!requestor.isCertprofilePermitted(certprofileName)) {
        addErrCertResp(resps, certReqId, notAuthorized,
            "certprofile " + certprofileName + " is not allowed");
        continue;
      }

      if (publicKey != null) {
        if (!req.hasProofOfPossession()) {
          addErrCertResp(resps, certReqId, badPOP, "no POP");
          continue;
        }

        if (!verifyPopo(req, publicKey, requestor.isRa())) {
          LOG.warn("could not validate POP for request {}", certReqId.getValue());
          addErrCertResp(resps, certReqId, badPOP, "invalid POP");
          continue;
        }
      } else {
        if (allowKeyGen) {
          checkPermission(requestor, PermissionConstants.GEN_KEYPAIR);
        } else {
          LOG.warn("no public key is specified and key generation is not allowed {}",
              certReqId.getValue());
          addErrCertResp(resps, certReqId, badCertTemplate, "no public key");
          continue;
        }
      }

      boolean caGenerateKeypair = publicKey == null;

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

      certTemplateDatas.add(new CertTemplateData(subject, publicKey, notBefore, notAfter,
          extensions, certprofileName, certReqId, caGenerateKeypair));
    } // end for

    if (resps.size() == n) {
      // all error
      CertResponse[] certResps = new CertResponse[n];
      for (int i = 0; i < n; i++) {
        certResps[i] = resps.get(i);
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
      CertResponse failCertResp = resps.get(lastFailureIndex);
      PKIStatus failStatus = PKIStatus.getInstance(
          new ASN1Integer(failCertResp.getStatus().getStatus()));
      PKIFailureInfo failureInfo = new PKIFailureInfo(failCertResp.getStatus().getFailInfo());

      CertResponse[] certResps = new CertResponse[n];

      for (int i = 0; i < n; i++) {
        if (i == lastFailureIndex) {
          certResps[i] = failCertResp;
          continue;
        }

        PKIStatusInfo tmpStatus = generateRejectionStatus(failStatus, failureInfo.intValue(),
            "error in certReq " + failCertReqId);
        certResps[i] = new CertResponse(certResps[i].getCertReqId(), tmpStatus);
      }

      return new CertRepMessage(null, certResps);
    }

    List<CertResponse> generateCertResponses = generateCertificates(certTemplateDatas, requestor,
        tid, kup, request, cmpControl, msgId, event);

    CertResponse[] certResps = new CertResponse[n];
    int index = 0;
    for (CertResponse errorResp : resps) {
      // error single CertResponse
      certResps[index++] = errorResp;
    }

    for (CertResponse certResp : generateCertResponses) {
      certResps[index++] = certResp;
    }

    CMPCertificate[] caPubs = null;
    if (cmpControl.isSendCaCert() || cmpControl.isSendCertChain()) {
      boolean anyCertEnrolled = false;
      for (CertResponse certResp : generateCertResponses) {
        if (certResp.getCertifiedKeyPair() != null) {
          anyCertEnrolled = true;
          break;
        }
      }

      if (anyCertEnrolled ) {
        List<CMPCertificate> certchain = new ArrayList<>(2);
        certchain.add(getCa().getCaInfo().getCertInCmpFormat());
        if (cmpControl.isSendCertChain()) {
          certchain.addAll(getCa().getCaInfo().getCertchainInCmpFormat());
        }

        caPubs = certchain.toArray(new CMPCertificate[0]);
      }
    }

    return new CertRepMessage(caPubs, certResps);
  } // method processCertReqMessages

  /**
   * handle the PKI body with the choice {@code p10cr}<br/>
   * Since it is not possible to add attribute to the PKCS#10 request (CSR), the certificate
   * profile must be specified in the attribute regInfo-utf8Pairs (1.3.6.1.5.5.7.5.2.1) within
   * PKIHeader.generalInfo
   */
  private PKIBody processP10cr(String dfltCertprofileName, PKIMessage request,
      CmpRequestorInfo requestor, ASN1OctetString tid, PKIHeader reqHeader,
      CertificationRequest p10cr, CmpControl cmpControl, String msgId, AuditEvent event) {
    // verify the POP first
    CertResponse certResp = null;
    ASN1Integer certReqId = new ASN1Integer(-1);

    boolean certGenerated = false;
    X509Ca ca = getCa();

    if (!ca.verifyCsr(p10cr)) {
      LOG.warn("could not validate POP for the pkcs#10 requst");
      certResp = buildErrCertResp(certReqId, badPOP, "invalid POP");
    } else {
      CertificationRequestInfo certTemp = p10cr.getCertificationRequestInfo();

      Extensions extensions;
      try {
        extensions = CaUtil.getExtensions(certTemp);
      } catch (IllegalArgumentException ex) {
        extensions = null;
        LOG.warn("could not parse extensions of the pkcs#10 requst");
        certResp = buildErrCertResp(certReqId, badCertTemplate, "invalid extensions");
      }

      if (certResp == null) {
        X500Name subject = certTemp.getSubject();
        SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();

        InfoTypeAndValue[] generalInfo = reqHeader.getGeneralInfo();
        CmpUtf8Pairs keyvalues = CmpUtil.extractUtf8Pairs(generalInfo);

        // CertProfile name
        String certprofileName = null;
        String[] list = CmpUtil.extractCertProfile(generalInfo);
        if (list != null && list.length > 0) {
          certprofileName = list[0];
        } else {
          if (keyvalues != null) {
            certprofileName = keyvalues.value(KEY_CERTPROFILE);
          }
        }

        // NotBefore and NotAfter
        Date notBefore = null;
        Date notAfter = null;

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
          if (!requestor.isCertprofilePermitted(certprofileName)) {
            String msg = "certprofile " + certprofileName + " is not allowed";
            certResp = buildErrCertResp(certReqId, notAuthorized, msg);
          } else {
            CertTemplateData certTemplateData = new CertTemplateData(subject, publicKeyInfo,
                notBefore, notAfter, extensions, certprofileName, certReqId, false);

            certResp = generateCertificates(Collections.singletonList(certTemplateData),
                requestor, tid, false, request, cmpControl, msgId, event).get(0);
            certGenerated = true;
          }
        }
      }
    }

    CMPCertificate[] caPubs = null;

    if (certGenerated && (cmpControl.isSendCaCert() || cmpControl.isSendCertChain())) {
      List<CMPCertificate> certchain = new ArrayList<>(2);
      certchain.add(getCa().getCaInfo().getCertInCmpFormat());
      if (cmpControl.isSendCertChain()) {
        certchain.addAll(getCa().getCaInfo().getCertchainInCmpFormat());
      }

      caPubs = certchain.toArray(new CMPCertificate[0]);
    }

    if (event.getStatus() == null || event.getStatus() != AuditStatus.FAILED) {
      int status = certResp.getStatus().getStatus().intValue();
      if (status != GRANTED && status != GRANTED_WITH_MODS && status != WAITING) {
        event.setStatus(AuditStatus.FAILED);
        PKIFreeText statusStr = certResp.getStatus().getStatusString();
        if (statusStr != null) {
          event.addEventData(CaAuditConstants.NAME_message, statusStr.getStringAt(0).getString());
        }
      }
    }

    return new PKIBody(PKIBody.TYPE_CERT_REP,
        new CertRepMessage(caPubs, new CertResponse[]{certResp}));
  } // method processP10cr

  private List<CertResponse> generateCertificates(List<CertTemplateData> certTemplates,
      CmpRequestorInfo requestor, ASN1OctetString tid, boolean kup, PKIMessage request,
      CmpControl cmpControl, String msgId, AuditEvent event) {
    X509Ca ca = getCa();

    final int n = certTemplates.size();
    List<CertResponse> ret = new ArrayList<>(n);

    if (cmpControl.isGroupEnroll()) {
      List<CertificateInfo> certInfos = null;
      try {
        certInfos = kup
            ? ca.regenerateCerts(certTemplates, requestor, RequestType.CMP, tid.getOctets(), msgId)
            : ca.generateCerts(certTemplates,   requestor, RequestType.CMP, tid.getOctets(), msgId);

        // save the request
        Long reqDbId = null;
        if (ca.getCaInfo().isSaveRequest()) {
          try {
            reqDbId = ca.addRequest(request.getEncoded());
          } catch (Exception ex) {
            LOG.warn("could not save request");
          }
        }

        for (int i = 0; i < n; i++) {
          CertificateInfo certInfo = certInfos.get(i);

          ASN1Integer certReqId = certTemplates.get(i).getCertReqId();
          if (cmpControl.isConfirmCert()) {
            pendingCertPool.addCertificate(tid.getOctets(), certReqId.getPositiveValue(), certInfo,
                System.currentTimeMillis() + cmpControl.getConfirmWaitTimeMs());
          }
          ret.add(postProcessCertInfo(certReqId, requestor, certInfo));

          if (reqDbId != null) {
            ca.addRequestCert(reqDbId, certInfo.getCert().getCertId());
          }
        }
      } catch (OperationException ex) {
        if (certInfos != null) {
          for (CertificateInfo certInfo : certInfos) {
            BigInteger sn = certInfo.getCert().getCert().getSerialNumber();
            try {
              ca.revokeCert(sn, CrlReason.CESSATION_OF_OPERATION, null, msgId);
            } catch (OperationException ex2) {
              LogUtil.error(LOG, ex2, "CA " + getCaName() + " could not revoke certificate " + sn);
            }
          }
        }
        event.setStatus(AuditStatus.FAILED);
        ret.clear();
        for (CertTemplateData certTemplate : certTemplates) {
          ret.add(postProcessException(certTemplate.getCertReqId(), ex));
        }
      }
    } else {
      Long reqDbId = null;
      boolean savingRequestFailed = false;

      for (CertTemplateData certTemplate : certTemplates) {
        ASN1Integer certReqId = certTemplate.getCertReqId();

        CertificateInfo certInfo;
        try {
          certInfo = kup
                  ? ca.regenerateCert(certTemplate, requestor, RequestType.CMP,
                      tid.getOctets(), msgId)
                  : ca.generateCert(certTemplate, requestor, RequestType.CMP,
                      tid.getOctets(), msgId);

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

          ret.add(postProcessCertInfo(certReqId, requestor, certInfo));
        } catch (OperationException ex) {
          event.setStatus(AuditStatus.FAILED);
          ret.add(postProcessException(certReqId, ex));
        }
      }
    }

    return ret;
  } // method generateCertificates

  private PKIBody unRevokeRemoveCertificates(PKIMessage request, RevReqContent rr,
      int permission, CmpControl cmpControl, String msgId, AuditEvent event) {
    RevDetails[] revContent = rr.toRevDetailsArray();

    RevRepContentBuilder repContentBuilder = new RevRepContentBuilder();
    // test the request
    for (RevDetails revDetails : revContent) {
      CertTemplate certDetails = revDetails.getCertDetails();
      X500Name issuer = certDetails.getIssuer();
      ASN1Integer serialNumber = certDetails.getSerialNumber();

      try {
        X500Name caSubject = getCa().getCaInfo().getCert().getSubject();

        if (issuer == null) {
          return buildErrorMsgPkiBody(rejection, badCertTemplate, "issuer is not present");
        }

        if (!issuer.equals(caSubject)) {
          return buildErrorMsgPkiBody(rejection, badCertTemplate,
                  "issuer does not target at the CA");
        }

        if (serialNumber == null) {
          return buildErrorMsgPkiBody(rejection, badCertTemplate, "serialNumber is not present");
        }

        if (certDetails.getSigningAlg() != null || certDetails.getValidity() != null
                || certDetails.getSubject() != null || certDetails.getPublicKey() != null
                || certDetails.getIssuerUID() != null || certDetails.getSubjectUID() != null) {
          return buildErrorMsgPkiBody(rejection, badCertTemplate, "only version, issuer and "
                  + "serialNumber in RevDetails.certDetails are allowed, but more is specified");
        }

        if (certDetails.getExtensions() == null) {
          if (cmpControl.isRrAkiRequired()) {
            return buildErrorMsgPkiBody(rejection, badCertTemplate, "issuer's AKI not present");
          }
        } else {
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
          if (ext == null) {
            return buildErrorMsgPkiBody(rejection, badCertTemplate, "issuer's AKI not present");
          } else {
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(ext.getParsedValue());

            if (aki.getKeyIdentifier() == null) {
              return buildErrorMsgPkiBody(rejection, badCertTemplate, "issuer's AKI not present");
            }

            boolean issuerMatched = true;

            byte[] caSki = getCa().getCaInfo().getCert().getSubjectKeyId();
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
              return buildErrorMsgPkiBody(rejection, badCertTemplate,
                      "issuer does not target at the CA");
            }
          }
        }
      } catch (IllegalArgumentException ex) {
        return buildErrorMsgPkiBody(rejection, badRequest, "the request is not invalid");
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

    for (RevDetails revDetails : revContent) {
      CertTemplate certDetails = revDetails.getCertDetails();
      ASN1Integer serialNumber = certDetails.getSerialNumber();
      // serialNumber is not null due to the check in the previous for-block.

      X500Name caSubject = getCa().getCaInfo().getCert().getSubject();
      BigInteger snBigInt = serialNumber.getPositiveValue();
      CertId certId = new CertId(new GeneralName(caSubject), serialNumber);

      PKIStatusInfo status;

      try {
        Object returnedObj;
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
        status = new PKIStatusInfo(granted);
      } catch (OperationException ex) {
        ErrorCode code = ex.getErrorCode();
        LOG.warn("{}, OperationException: code={}, message={}",
                PermissionConstants.getTextForCode(permission), code.name(), ex.getErrorMessage());
        String errorMsg = (code == ErrorCode.DATABASE_FAILURE || code == ErrorCode.SYSTEM_FAILURE)
                ? code.name() : code.name() + ": " + ex.getErrorMessage();

        int failureInfo = getPKiFailureInfo(ex);
        status = generateRejectionStatus(failureInfo, errorMsg);
        event.update(AuditLevel.ERROR, AuditStatus.FAILED);
        event.addEventData(CaAuditConstants.NAME_message, errorMsg);
      } // end try

      repContentBuilder.add(status, certId);
    } // end for

    return new PKIBody(PKIBody.TYPE_REVOCATION_REP, repContentBuilder.build());
  } // method revokeOrUnrevokeOrRemoveCertificates

  @Override
  protected PKIBody confirmCertificates(ASN1OctetString transactionId, CertConfirmContent certConf,
      String msgId) {
    CertStatus[] certStatuses = certConf.toCertStatusArray();

    boolean successful = true;
    for (CertStatus certStatus : certStatuses) {
      ASN1Integer certReqId = certStatus.getCertReqId();
      byte[] certHash = certStatus.getCertHash().getOctets();
      CertificateInfo certInfo = pendingCertPool.removeCertificate(
          transactionId.getOctets(), certReqId.getPositiveValue(), certHash);
      if (certInfo == null) {
        LOG.warn("no cert under transactionId={}, certReqId={} and certHash=0X{}",
            transactionId, certReqId.getPositiveValue(), Hex.encode(certHash));
        continue;
      }

      PKIStatusInfo statusInfo = certStatus.getStatusInfo();
      boolean accept = true;
      if (statusInfo != null) {
        int status = statusInfo.getStatus().intValue();
        if (GRANTED != status && GRANTED_WITH_MODS != status) {
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
        new ErrorMsgContent(new PKIStatusInfo(rejection, null, new PKIFailureInfo(systemFailure))));
  } // method confirmCertificates

  @Override
  protected boolean revokePendingCertificates(ASN1OctetString transactionId, String msgId) {
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

  @Override
  protected PKIBody cmpEnrollCert(String dfltCertprofileName,
      PKIMessage request, PKIHeaderBuilder respHeader, CmpControl cmpControl, PKIHeader reqHeader,
      PKIBody reqBody, CmpRequestorInfo requestor, ASN1OctetString tid, String msgId,
      AuditEvent event) throws InsufficientPermissionException {
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
    if (type == PKIBody.TYPE_INIT_REQ) {
      checkPermission(requestor, PermissionConstants.ENROLL_CERT);
      CertReqMessages cr = CertReqMessages.getInstance(reqBody.getContent());
      CertRepMessage repMessage = processCertReqMessages(dfltCertprofileName,
          request, requestor, tid, cr, true, cmpControl, msgId, event);
      return new PKIBody(PKIBody.TYPE_INIT_REP, repMessage);
    } else if (type == PKIBody.TYPE_CERT_REQ) {
      checkPermission(requestor, PermissionConstants.ENROLL_CERT);
      CertReqMessages cr = CertReqMessages.getInstance(reqBody.getContent());
      CertRepMessage repMessage = processCertReqMessages(dfltCertprofileName,
          request, requestor, tid, cr, true, cmpControl, msgId, event);
      respBody = new PKIBody(PKIBody.TYPE_CERT_REP, repMessage);
    } else if (type == PKIBody.TYPE_KEY_UPDATE_REQ) {
      checkPermission(requestor, PermissionConstants.KEY_UPDATE);
      CertReqMessages kur = CertReqMessages.getInstance(reqBody.getContent());
      CertRepMessage repMessage = processCertReqMessages(dfltCertprofileName,
          request, requestor, tid, kur, true, cmpControl, msgId, event);
      return new PKIBody(PKIBody.TYPE_KEY_UPDATE_REP, repMessage);
    } else if (type == PKIBody.TYPE_P10_CERT_REQ) {
      checkPermission(requestor, PermissionConstants.ENROLL_CERT);
      respBody = processP10cr(dfltCertprofileName, request, requestor, tid, reqHeader,
          CertificationRequest.getInstance(reqBody.getContent()), cmpControl, msgId, event);
    } else if (type == PKIBody.TYPE_CROSS_CERT_REQ) {
      checkPermission(requestor, PermissionConstants.ENROLL_CROSS);
      CertReqMessages cr = CertReqMessages.getInstance(reqBody.getContent());
      CertRepMessage repMessage = processCertReqMessages(dfltCertprofileName,
          request, requestor, tid, cr, false, cmpControl, msgId, event);
      return new PKIBody(PKIBody.TYPE_CROSS_CERT_REP, repMessage);
    } else {
      throw new IllegalStateException("should not reach here");
    } // switch type

    InfoTypeAndValue tv;
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

  @Override
  protected PKIBody cmpUnRevokeRemoveCertificates(PKIMessage request, PKIHeaderBuilder respHeader,
      CmpControl cmpControl, PKIHeader reqHeader, PKIBody reqBody, CmpRequestorInfo requestor,
      String msgId, AuditEvent event) {
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

      if (reasonCode == XiSecurityConstants.CMP_CRL_REASON_REMOVE) {
        if (requiredPermission == null) {
          event.addEventType(CaAuditConstants.Cmp.TYPE_rr_remove);
          requiredPermission = PermissionConstants.REMOVE_CERT;
        } else if (requiredPermission != PermissionConstants.REMOVE_CERT) {
          allRevdetailsOfSameType = false;
          break;
        }
      } else if (reasonCode == CrlReason.REMOVE_FROM_CRL.getCode()) {
        if (requiredPermission == null) {
          event.addEventType(CaAuditConstants.Cmp.TYPE_rr_unrevoke);
          requiredPermission = PermissionConstants.UNREVOKE_CERT;
        } else if (requiredPermission != PermissionConstants.UNREVOKE_CERT) {
          allRevdetailsOfSameType = false;
          break;
        }
      } else {
        if (requiredPermission == null) {
          event.addEventType(CaAuditConstants.Cmp.TYPE_rr_revoke);
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

    return unRevokeRemoveCertificates(request, rr, requiredPermission, cmpControl, msgId, event);
  } // method cmpRevokeOrUnrevokeOrRemoveCertificates

  @Override
  protected PKIBody cmpGeneralMsg(PKIHeaderBuilder respHeader, CmpControl cmpControl,
      PKIHeader reqHeader, PKIBody reqBody, CmpRequestorInfo requestor, ASN1OctetString tid,
      String msgId, AuditEvent event) throws InsufficientPermissionException {
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
      return buildErrorMsgPkiBody(rejection, badRequest, statusMessage);
    }

    InfoTypeAndValue itvResp = null;
    ASN1ObjectIdentifier infoType = itv.getInfoType();

    int failureInfo;
    try {
      X509Ca ca = getCa();
      if (CMPObjectIdentifiers.it_currentCRL.equals(infoType)) {
        event.addEventType(CaAuditConstants.Cmp.TYPE_genm_current_crl);
        checkPermission(requestor, PermissionConstants.GET_CRL);
        CertificateList crl;

        if (itv.getInfoValue() == null) { // as defined in RFC 4210
          crl = ca.getBcCurrentCrl(msgId);
        } else {
          // xipki extension
          ASN1Integer crlNumber = ASN1Integer.getInstance(itv.getInfoValue());
          crl = ca.getBcCrl(crlNumber.getPositiveValue(), msgId);
        }

        if (crl == null) {
          return buildErrorMsgPkiBody(rejection, systemFailure, "no CRL is available");
        }

        itvResp = new InfoTypeAndValue(infoType, crl);
      } else if (ObjectIdentifiers.Xipki.id_xipki_cmp_cmpGenmsg.equals(infoType)) {
        ASN1Encodable asn1 = itv.getInfoValue();
        ASN1Integer asn1Code;
        ASN1Encodable reqValue = null;

        try {
          ASN1Sequence seq = ASN1Sequence.getInstance(asn1);
          asn1Code = ASN1Integer.getInstance(seq.getObjectAt(0));
          if (seq.size() > 1) {
            reqValue = seq.getObjectAt(1);
          }
        } catch (IllegalArgumentException ex) {
          return buildErrorMsgPkiBody(rejection, badRequest,
              "invalid value of the InfoTypeAndValue for " + infoType.getId());
        }

        ASN1Encodable respValue;

        int action = asn1Code.getPositiveValue().intValue();
        if (action == XiSecurityConstants.CMP_ACTION_GEN_CRL) {
          event.addEventType(CaAuditConstants.Cmp.TYPE_genm_gen_crl);
          checkPermission(requestor, PermissionConstants.GEN_CRL);
          X509CRLHolder tmpCrl = ca.generateCrlOnDemand(msgId);
          if (tmpCrl == null) {
            return buildErrorMsgPkiBody(rejection, systemFailure,
                    "CRL generation is not activated");
          } else {
            respValue = tmpCrl.toASN1Structure();
          }
        } else if (action == XiSecurityConstants.CMP_ACTION_GET_CRL_WITH_SN) {
          event.addEventType(CaAuditConstants.Cmp.TYPE_genm_crl4number);
          checkPermission(requestor, PermissionConstants.GET_CRL);

          respValue = ca.getBcCrl(ASN1Integer.getInstance(reqValue).getPositiveValue(), msgId);
          if (respValue == null) {
            return buildErrorMsgPkiBody(rejection, systemFailure, "no CRL is available");
          }
        } else if (action == XiSecurityConstants.CMP_ACTION_GET_CAINFO) {
          event.addEventType(CaAuditConstants.Cmp.TYPE_genm_cainfo);
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
            acceptVersions.add(3);
          }

          String systemInfo = getSystemInfo(requestor, acceptVersions);
          respValue = new DERUTF8String(systemInfo);
        } else if (action == XiSecurityConstants.CMP_ACTION_CACERTCHAIN) {
          event.addEventType(CaAuditConstants.Cmp.TYPE_genm_cacertchain);
          ASN1EncodableVector vec = new ASN1EncodableVector();
          vec.add(ca.getCaInfo().getCertInCmpFormat());
          List<X509Cert> certchain = ca.getCaInfo().getCertchain();
          if (CollectionUtil.isNotEmpty(certchain)) {
            for (X509Cert m : certchain) {
              vec.add(m.toBcCert().toASN1Structure());
            }
          }
          respValue = new DERSequence(vec);
        } else {
          return buildErrorMsgPkiBody(rejection, badRequest,
                  "unsupported XiPKI action code " + action);
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(asn1Code);
        if (respValue != null) {
          vec.add(respValue);
        }
        itvResp = new InfoTypeAndValue(infoType, new DERSequence(vec));
      }

      GenRepContent genRepContent = new GenRepContent(itvResp);
      return new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);
    } catch (OperationException ex) {
      failureInfo = getPKiFailureInfo(ex);
      ErrorCode code = ex.getErrorCode();

      String errorMessage =
          (code == ErrorCode.DATABASE_FAILURE || code == ErrorCode.SYSTEM_FAILURE)
          ? code.name() : code.name() + ": " + ex.getErrorMessage();

      return buildErrorMsgPkiBody(rejection, failureInfo, errorMessage);
    }
  } // method cmpGeneralMsg

}
