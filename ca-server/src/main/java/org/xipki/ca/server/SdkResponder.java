/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
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

package org.xipki.ca.server;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.ca.api.*;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.sdk.*;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.CrlReason;
import org.xipki.security.util.HttpRequestMetadataRetriever;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;
import org.xipki.util.exception.InsufficientPermissionException;
import org.xipki.util.exception.OperationException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.xipki.util.exception.OperationException.ErrorCode.*;
import static org.xipki.ca.sdk.SdkConstants.*;
import static org.xipki.ca.sdk.CaAuditConstants.*;
import static org.xipki.util.PermissionConstants.*;

/**
 * SDK responder.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class SdkResponder {

  private class PendingPoolCleaner implements Runnable {

    @Override
    public void run() {
      Set<CertificateInfo> remainingCerts = pendingCertPool.removeConfirmTimeoutedCertificates();
      if (CollectionUtil.isEmpty(remainingCerts)) {
        return;
      }

      Date invalidityDate = new Date();
      X509Ca ca = null;
      for (CertificateInfo remainingCert : remainingCerts) {
        String caName = remainingCert.getIssuer().getName();
        BigInteger serialNumber = remainingCert.getCert().getCert().getSerialNumber();

        if (ca == null || !ca.getCaIdent().getName().equals(caName)) {
          try {
            ca = caManager.getX509Ca(caName);
          } catch (CaMgmtException e) {
            LOG.error("could not revoke certificate (CA={}, serialNumber={}): unknown CA",
                caName, LogUtil.formatCsn(serialNumber));
            continue;
          }
        }

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

  private static final int DFLT_CONFIRM_WAIT_TIME_MS = 600 * 1000; // 10 minutes
  private final PendingCertificatePool pendingCertPool;

  private static final Logger LOG = LoggerFactory.getLogger(SdkResponder.class);

  private static final Set<String> kupCertExtnIds;

  private final CaManagerImpl caManager;

  static {
    kupCertExtnIds = new HashSet<>();
    kupCertExtnIds.add(Extension.biometricInfo.getId());
    kupCertExtnIds.add(Extension.extendedKeyUsage.getId());
    kupCertExtnIds.add(Extension.keyUsage.getId());
    kupCertExtnIds.add(Extension.qCStatements.getId());
    kupCertExtnIds.add(Extension.subjectAlternativeName.getId());
    kupCertExtnIds.add(Extension.subjectInfoAccess.getId());
  }

  public SdkResponder(CaManagerImpl caManager) {
    this.caManager = Args.notNull(caManager, "caManager");
    this.pendingCertPool = new PendingCertificatePool();
    caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(
        new PendingPoolCleaner(), 10, 10, TimeUnit.MINUTES);
  }

  public SdkResponse service(
      String path, AuditEvent event, byte[] request,
      HttpRequestMetadataRetriever httpRetriever) {
    AuditLevel auditLevel = AuditLevel.INFO;
    AuditStatus auditStatus = AuditStatus.SUCCESSFUL;
    String auditMessage = null;

    try {
      SdkResponse resp = service0(path, event, request, httpRetriever);
      if (resp instanceof ErrorResponse) {
        auditLevel = AuditLevel.ERROR;
        auditStatus = AuditStatus.FAILED;
        auditMessage = ((ErrorResponse) resp).getMessage();
      }
      return resp;
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      auditLevel = AuditLevel.ERROR;
      auditStatus = AuditStatus.FAILED;
      auditMessage = "internal error";
      return new ErrorResponse(null, SYSTEM_FAILURE, auditMessage);
    } finally {
      event.setStatus(auditStatus);
      event.setLevel(auditLevel);
      if (auditMessage != null) {
        event.addEventData(NAME_message, auditMessage);
      }
    }
  }

  private SdkResponse service0(
      String path, AuditEvent event, byte[] request,
      HttpRequestMetadataRetriever httpRetriever) {
    event.setApplicationName(APPNAME);
    event.setName(NAME_perf);

    String msgId = RandomUtil.nextHexLong();
    event.addEventData(NAME_mid, msgId);

    try {
      if (caManager == null) {
        return new ErrorResponse(null, SYSTEM_FAILURE,
            "responderManager in servlet not configured");
      }

      String caName = null;
      String command = null;

      X509Ca ca = null;
      if (path.length() > 1) {
        // the first char is always '/'
        String coreUri = path;
        int sepIndex = coreUri.indexOf('/', 1);
        if (sepIndex == -1 || sepIndex == coreUri.length() - 1) {
          return new ErrorResponse(null, PATH_NOT_FOUND, "invalid path " + path);
        }

        // skip also the first char ('/')
        String caAlias = coreUri.substring(1, sepIndex).toLowerCase();
        command = coreUri.substring(sepIndex + 1).toLowerCase();

        caName = caManager.getCaNameForAlias(caAlias);
        if (caName == null) {
          caName = caAlias;
        }

        try {
          ca = caManager.getX509Ca(caName);
        } catch (CaMgmtException e) {
          return new ErrorResponse(null, PATH_NOT_FOUND,
              "CA unknown");
        }
      }

      if (StringUtil.isBlank(command)) {
        return new ErrorResponse(null, PATH_NOT_FOUND,
            "command is not specified");
      }

      if (ca == null || ca.getCaInfo().getStatus() != CaStatus.ACTIVE) {
        String message = (ca == null) ? "unknown CA '" + caName + "'"
            : "CA '" + caName + "' is out of service";
        return new ErrorResponse(null, PATH_NOT_FOUND, message);
      }

      event.addEventData(NAME_ca, ca.getCaIdent().getName());
      event.addEventType(command);

      X509Cert clientCert;
      try {
        clientCert = httpRetriever.getTlsClientCert();
      } catch (IOException ex) {
        LogUtil.error(LOG, ex, "error getTlsClientCert");
        return new ErrorResponse(null, UNAUTHORIZED, "error retrieving client certificate");
      }
      if (clientCert == null) {
        return new ErrorResponse(null, UNAUTHORIZED, "no client certificate");
      }
      RequestorInfo requestor = ca.getRequestor(clientCert);

      if (requestor == null) {
        return new ErrorResponse(null, NOT_PERMITTED, "no requestor specified");
      }

      event.addEventData(NAME_requestor, requestor.getIdent().getName());

      switch (command) {
        case CMD_health: {
          boolean healthy = ca.healthy();
          return healthy ? null : new ErrorResponse(null, SYSTEM_UNAVAILABLE,
                              "CA is not healthy");
        }
        case CMD_cacert: {
          byte[][] certs = new byte[1][];
          certs[0] = ca.getCaInfo().getCert().getEncoded();
          CertChainResponse resp = new CertChainResponse();
          resp.setCertificates(certs);
          return resp;
        }
        case CMD_cacertchain: {
          List<X509Cert> certchain = ca.getCaInfo().getCertchain();
          int size = 1 + (certchain == null ? 0 : certchain.size());
          byte[][] certs = new byte[size][];
          certs[0] = ca.getCaInfo().getCert().getEncoded();
          if (size > 1) {
            for (int i = 1; i < size; i++) {
              certs[i] = certchain.get(i - 1).getEncoded();
            }
          }

          CertChainResponse resp = new CertChainResponse();
          resp.setCertificates(certs);
          return resp;
        }
        case CMD_enroll: {
          assertPermitted(requestor, ENROLL_CERT);
          return enroll(ca, request, requestor, msgId, false, event);
        }
        case CMD_enroll_kup: {
          assertPermitted(requestor, KEY_UPDATE);
          return enroll(ca, request, requestor, msgId, true, event);
        }
        case CMD_poll_cert: {
          if (!(requestor.isPermitted(ENROLL_CERT) || requestor.isPermitted(KEY_UPDATE))) {
            throw new OperationException(NOT_PERMITTED);
          }
          return poll(ca, request, requestor);
        }
        case CMD_revoke_cert: {
          assertPermitted(requestor, REVOKE_CERT);
          return revoke(ca, request, msgId);
        }
        case CMD_confirm_enroll: {
          if (!(requestor.isPermitted(ENROLL_CERT) || requestor.isPermitted(KEY_UPDATE))) {
            throw new OperationException(NOT_PERMITTED);
          }
          return confirmCertificates(ca, request, msgId);
        }
        case CMD_revoke_pending_cert: {
          if (!(requestor.isPermitted(ENROLL_CERT) || requestor.isPermitted(KEY_UPDATE))) {
            throw new OperationException(NOT_PERMITTED);
          }
          TransactionIdRequest req = TransactionIdRequest.decode(request);
          revokePendingCertificates(ca, req.getTid(), msgId);
          return null;
        }
        case CMD_unrevoke_cert:
        case CMD_remove_cert: {
          boolean unrevoke = CMD_unrevoke_cert.equals(command);
          assertPermitted(requestor, unrevoke
              ? UNREVOKE_CERT : REMOVE_CERT);
          return removeOrUnrevoke(ca, request, msgId, unrevoke);
        }
        case CMD_gen_crl: {
          assertPermitted(requestor, GEN_CRL);
          return genCrl(ca, request, msgId);
        }
        case CMD_crl: {
          assertPermitted(requestor, GET_CRL);
          return getCrl(ca, request, msgId);
        }
        case CMD_get_cert: {
          assertPermitted(requestor, GET_CERT);
          return getCert(ca, request, msgId);
        }
        default: {
          return new ErrorResponse(null, PATH_NOT_FOUND, "invalid command '" + command + "'");
        }
      }
    } catch (OperationException ex) {
      return new ErrorResponse(null, ex.getErrorCode(), ex.getErrorMessage());
    }
  } // method service

  private SdkResponse enroll(
      X509Ca ca, byte[] request, RequestorInfo requestor, String msgId,
      boolean keyUpdate, AuditEvent event) throws OperationException {
    EnrollCertsRequest req = EnrollCertsRequest.decode(request);
    for (EnrollCertRequestEntry entry : req.getEntries()) {
      String profile = entry.getCertprofile();
      if (!requestor.isCertprofilePermitted(profile)) {
        throw new OperationException(NOT_PERMITTED,
            "certprofile " + profile + " is not allowed");
      }
    }

    List<CertTemplateData> certTemplates = new ArrayList<>(req.getEntries().size());

    List<EnrollCertRequestEntry> entries = req.getEntries();
    for (EnrollCertRequestEntry entry : entries) {
      String profile = entry.getCertprofile();
      Long notBeforeInSec = entry.getNotBefore();
      Date notBefore = (notBeforeInSec == null) ? null : new Date(notBeforeInSec * 1000);

      Long notAfterInSec = entry.getNotAfter();
      Date notAfter = (notAfterInSec == null) ? null : new Date(notAfterInSec * 1000);

      X500Name subject = null;
      Extensions extensions = null;
      SubjectPublicKeyInfo publicKeyInfo = null;

      if (entry.getP10req() != null) {
        // The PKCS#10 will only be used for transport of public key, subject and extensions.
        // The verification of POP is skipped here.
        CertificationRequestInfo certTemp =
            CertificationRequest.getInstance(entry.getP10req()).getCertificationRequestInfo();
        subject = certTemp.getSubject();
        publicKeyInfo = certTemp.getSubjectPublicKeyInfo();
        extensions = X509Util.getExtensions(certTemp);
      } else {
        X500NameType subject0 = entry.getSubject();
        if (subject0 == null) {
          if (!keyUpdate) {
            throw new OperationException(BAD_CERT_TEMPLATE, "subject is not set");
          }
        } else {
          try {
            subject = subject0.toX500Name();
          } catch (IOException ex) {
            throw new OperationException(BAD_CERT_TEMPLATE);
          }
        }

        if (entry.getExtensions() != null) {
          extensions = Extensions.getInstance(entry.getExtensions());
        }

        if (entry.getSubjectPublicKey() != null) {
          publicKeyInfo = SubjectPublicKeyInfo.getInstance(entry.getSubjectPublicKey());
        }

        if (keyUpdate) {
          OldCertInfo oc = entry.getOldCert();
          if (oc == null) {
            throw new OperationException(BAD_CERT_TEMPLATE,
                "oldCert is not specified in enroll_kup command");
          }

          X500Name issuer = X500Name.getInstance(oc.getIssuer());
          BigInteger serialNumber = oc.getSerialNumber();
          CertWithRevocationInfo oldCert;
          try {
            oldCert = caManager.getCert(issuer, serialNumber);
          } catch (CaMgmtException ex) {
            // TODO: LOG me
            throw new OperationException(SYSTEM_FAILURE,
                "error while finding certificate with "
                    + "the issuer " + issuer + "and serial number " + serialNumber);
          }

          if (oldCert == null) {
            throw new OperationException(UNKNOWN_CERT,
                "found no certificate with the issuer "
                    + issuer + "and serial number " + serialNumber);
          }

          if (oldCert.isRevoked()) {
            throw new OperationException(CERT_REVOKED,
                "could not update a revoked certificate "
                    + "with the issuer " + issuer + "and serial number " + serialNumber);
          }

          if (profile == null) {
            profile = oldCert.getCertprofile();
          }

          if (subject == null) {
            subject = oldCert.getCert().getCert().getSubject();
          }

          if (publicKeyInfo == null && oc.isReusePublicKey()) {
            publicKeyInfo = oldCert.getCert().getCert().getSubjectPublicKeyInfo();
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
      }

      boolean caGenerateKeypair = publicKeyInfo == null;
      CertTemplateData certTemplate = new CertTemplateData(subject, publicKeyInfo,
          notBefore, notAfter, extensions, profile, entry.getCertReqId(), caGenerateKeypair);
      certTemplates.add(certTemplate);
    }

    long waitForConfirmUtil = 0;
    boolean explicitConform = req.getExplicitConfirm() != null && req.getExplicitConfirm();

    if (explicitConform) {
      int confirmWaitTimeMs = req.getConfirmWaitTimeMs() == null
          ? DFLT_CONFIRM_WAIT_TIME_MS : req.getConfirmWaitTimeMs();
      waitForConfirmUtil = System.currentTimeMillis() + confirmWaitTimeMs;
    }

    List<EnrollOrPullCertResponseEntry> rentries =
        generateCertificates(ca, certTemplates, requestor,
        keyUpdate, req, request, waitForConfirmUtil, msgId, event);
    EnrollOrPollCertsResponse resp = new EnrollOrPollCertsResponse();
    resp.setTransactionId(req.getTransactionId());

    if (rentries != null) {
      resp.setEntries(rentries);
      if (explicitConform) {
        resp.setConfirmWaitTime(waitForConfirmUtil);
      }

      CertsMode caCertMode = req.getCaCertMode();
      if (caCertMode == CertsMode.CERT) {
        resp.setExtraCerts(Collections.singletonList(ca.getCaCert().getEncoded()));
      } else if (caCertMode == CertsMode.CHAIN) {
        List<X509Cert> chain = ca.getCaInfo().getCertchain();
        if (CollectionUtil.isEmpty(chain)) {
          resp.setExtraCerts(Collections.singletonList(ca.getCaCert().getEncoded()));
        } else {
          resp.setExtraCerts(ca.getEncodedCaCertChain());
        }
      }
    }
    return resp;
  } // enroll

  private SdkResponse poll(
      X509Ca ca, byte[] request, RequestorInfo requestor)
      throws OperationException {
    PollCertRequest req = PollCertRequest.decode(request);
    for (PollCertRequestEntry m : req.getEntries()) {
    }
    // TODO
    return null;
  }

  private SdkResponse revoke(X509Ca ca, byte[] request, String msgId)
      throws OperationException {
    RevokeCertsRequest req = RevokeCertsRequest.decode(request);
    X500Name issuer;
    try {
      issuer = req.getIssuer().toX500Name();
    } catch (IOException e) {
      throw new OperationException(BAD_REQUEST, "error toX500Name");
    }
    byte[] aki = req.getAuthorityKeyIdentifier();
    assertCaMatch(ca.getCaCert(), issuer, aki);

    List<RevokeCertRequestEntry> entries = req.getEntries();
    List<SingleCertSerialEntry> rentries = new ArrayList<>(entries.size());
    for (RevokeCertRequestEntry entry : entries) {
      BigInteger serialNumber = entry.getSerialNumber();
      SingleCertSerialEntry rentry = new SingleCertSerialEntry();
      rentries.add(rentry);

      rentry.setSerialNumber(serialNumber);

      CrlReason reason = entry.getReason();
      if (reason == CrlReason.REMOVE_FROM_CRL) {
        rentry.setError(new ErrorEntry(
            BAD_REQUEST, "Reason removeFromCRL is not permitted"));
      } else {
        Date invalidityTime = entry.getInvalidityTime() == null
            ? null : new Date(entry.getInvalidityTime() * 1000);
        try {
          ca.revokeCert(serialNumber, reason, invalidityTime, msgId);
        } catch (OperationException e) {
          rentry.setError(new ErrorEntry(e.getErrorCode(), e.getMessage()));
        }
      }
    }
    RevokeCertsResponse resp = new RevokeCertsResponse();
    resp.setEntries(rentries);
    return resp;
  }

  private SdkResponse removeOrUnrevoke(
      X509Ca ca, byte[] request, String msgId, boolean unrevoke)
      throws OperationException {
    UnrevokeOrRemoveCertsRequest req = UnrevokeOrRemoveCertsRequest.decode(request);
    X500Name issuer;
    try {
      issuer = req.getIssuer().toX500Name();
    } catch (IOException e) {
      throw new OperationException(BAD_REQUEST, "error toX500Name");
    }

    byte[] aki = req.getAuthorityKeyIdentifier();
    assertCaMatch(ca.getCaCert(), issuer, aki);

    List<BigInteger> entries = req.getEntries();
    List<SingleCertSerialEntry> rentries = new ArrayList<>(req.getEntries().size());

    for (BigInteger serialNumber : entries) {
      SingleCertSerialEntry rentry = new SingleCertSerialEntry();
      rentry.setSerialNumber(serialNumber);
      rentries.add(rentry);
      try {
        if (unrevoke) {
          ca.unrevokeCert(serialNumber, msgId);
        } else {
          ca.removeCert(serialNumber, msgId);
        }
      } catch (OperationException e) {
        rentry.setError(new ErrorEntry(e.getErrorCode(), e.getMessage()));
      }
    }

    UnrevokeOrRemoveCertsResponse resp = new UnrevokeOrRemoveCertsResponse();
    resp.setEntries(rentries);
    return resp;
  }

  private static void assertCaMatch(X509Cert caCert, X500Name issuer, byte[] aki)
      throws OperationException {
    X500Name caSubject = caCert.getSubject();

    if (issuer == null) {
      throw new OperationException(BAD_CERT_TEMPLATE, "issuer is not present");
    }

    if (!issuer.equals(caSubject)) {
      throw new OperationException(BAD_CERT_TEMPLATE, "issuer does not target at the CA");
    }

    byte[] caSki = caCert.getSubjectKeyId();
    if (!Arrays.equals(caSki, aki)) {
      throw new OperationException(BAD_CERT_TEMPLATE,
          "AuthorityKeyIdentifier does not target at the CA");
    }
  }

  private SdkResponse genCrl(X509Ca ca, byte[] request, String msgId)
      throws OperationException {
    GenCRLRequest req = GenCRLRequest.decode(request);
    // TODO: consider req
    X509CRLHolder crl = ca.generateCrlOnDemand(msgId);
    return buildCrlResp(crl, "generate CRL");
  }

  private SdkResponse getCrl(X509Ca ca, byte[] request, String msgId)
      throws OperationException {
    GetCRLRequest req = GetCRLRequest.decode(request);

    BigInteger crlNumber = req.getCrlNumber();
    X509CRLHolder crl = ca.getCrl(crlNumber, msgId);
    return buildCrlResp(crl, "get CRL");
  }

  private static SdkResponse buildCrlResp(X509CRLHolder crl, String desc) {
    if (crl == null) {
      String message = "could not " + desc;
      LOG.warn(message);
      return new ErrorResponse(null, SYSTEM_FAILURE, message);
    }

    try {
      CrlResponse resp = new CrlResponse();
      resp.setCrl(crl.getEncoded());
      return resp;
    } catch (IOException e) {
      return new ErrorResponse(null, SYSTEM_FAILURE, "error encoding CRL");
    }
  }


  private SdkResponse getCert(X509Ca ca, byte[] request, String msgId)
      throws OperationException {
    GetCertRequest req = GetCertRequest.decode(request);

    X500Name issuer;
    try {
      issuer = req.getIssuer().toX500Name();
    } catch (IOException e) {
      throw new OperationException(BAD_REQUEST, "error toX500Name");
    }
    if (!issuer.equals(ca.getCaCert().getSubject())) {
      throw new OperationException(BAD_REQUEST, "unknown issuer");
    }

    BigInteger sn = req.getSerialNumber();
    X509Cert cert;
    try {
      cert = ca.getCert(sn);
    } catch (CertificateException e) {
      throw new OperationException(SYSTEM_FAILURE, e.getMessage());
    }
    if (cert == null) {
      return null;
    }
    PayloadResponse resp = new PayloadResponse();
    resp.setPayload(cert.getEncoded());
    return resp;
  }


  private static void assertPermitted(RequestorInfo requestor, int permission)
      throws OperationException {
    try {
      requestor.assertPermitted(permission);
    } catch (InsufficientPermissionException ex) {
      throw new OperationException(NOT_PERMITTED, ex.getMessage());
    }
  }

  private List<EnrollOrPullCertResponseEntry> generateCertificates(
      X509Ca ca, List<CertTemplateData> certTemplates,
      RequestorInfo requestor, boolean kup, EnrollCertsRequest req,
      byte[] request, long waitForConfirmUtil, String msgId, AuditEvent event) {
    String caName = ca.getCaInfo().getIdent().getName();
    final int n = certTemplates.size();
    String tid = req.getTransactionId();

    Boolean b = req.getGroupEnroll();
    boolean groupEnroll = b == null || b;

    b = req.getExplicitConfirm();
    boolean explicitConfirm = b != null && b;

    List<EnrollOrPullCertResponseEntry> ret = new ArrayList<>(n);

    if (groupEnroll) {
      List<CertificateInfo> certInfos = null;
      try {
        certInfos = kup
            ? ca.regenerateCerts(certTemplates, requestor, tid, msgId)
            : ca.generateCerts(certTemplates,   requestor, tid, msgId);

        // save the request
        Long reqDbId = null;
        if (ca.getCaInfo().isSaveRequest()) {
          try {
            reqDbId = ca.addRequest(request);
          } catch (Exception ex) {
            LOG.warn("could not save request");
          }
        }

        for (int i = 0; i < n; i++) {
          CertificateInfo certInfo = certInfos.get(i);

          BigInteger certReqId = certTemplates.get(i).getCertReqId();
          if (explicitConfirm) {
            pendingCertPool.addCertificate(tid, certReqId, certInfo, waitForConfirmUtil);
          }

          ret.add(toResponseEntry(certInfo, certReqId));

          if (reqDbId != null) {
            ca.addRequestCert(reqDbId, certInfo.getCert().getCertId());
          }
        }

        return ret;
      } catch (OperationException ex) {
        if (certInfos != null) {
          for (CertificateInfo certInfo : certInfos) {
            BigInteger sn = certInfo.getCert().getCert().getSerialNumber();
            try {
              ca.revokeCert(sn, CrlReason.CESSATION_OF_OPERATION, null, msgId);
            } catch (OperationException ex2) {
              LogUtil.error(LOG, ex2, "CA " + caName + " could not revoke certificate " + sn);
            }
          }
        }
        event.setStatus(AuditStatus.FAILED);
        return null;
      }
    }

    Long reqDbId = null;
    boolean savingRequestFailed = false;

    for (CertTemplateData certTemplate : certTemplates) {
      BigInteger certReqId = certTemplate.getCertReqId();

      CertificateInfo certInfo;
      try {
        certInfo = kup
            ? ca.regenerateCert(certTemplate, requestor, tid, msgId)
            : ca.generateCert(certTemplate, requestor, tid, msgId);

        if (ca.getCaInfo().isSaveRequest()) {
          if (reqDbId == null && !savingRequestFailed) {
            try {
              reqDbId = ca.addRequest(request);
            } catch (Exception ex) {
              savingRequestFailed = true;
              LOG.warn("could not save request");
            }
          }

          if (reqDbId != null) {
            ca.addRequestCert(reqDbId, certInfo.getCert().getCertId());
          }
        }

        if (explicitConfirm) {
          pendingCertPool.addCertificate(tid, certReqId, certInfo, waitForConfirmUtil);
        }

        ret.add(toResponseEntry(certInfo, certReqId));
      } catch (OperationException ex) {
        event.setStatus(AuditStatus.FAILED);
        EnrollOrPullCertResponseEntry rentry = new EnrollOrPullCertResponseEntry();
        rentry.setError(new ErrorEntry(ex.getErrorCode(), ex.getMessage()));
        ret.add(rentry);
      }
    }

    for (EnrollOrPullCertResponseEntry m : ret) {
      if (m.getCert() != null) {
        return ret;
      }
    }

    // all requests failed
    return null;
  } // method generateCertificates

  private static EnrollOrPullCertResponseEntry toResponseEntry(
      CertificateInfo certInfo, BigInteger certReqId) {
    EnrollOrPullCertResponseEntry rentry = new EnrollOrPullCertResponseEntry();
    rentry.setId(certReqId);
    if (certInfo.getPrivateKey() != null) {
      try {
        rentry.setPrivateKey(certInfo.getPrivateKey().getEncoded());
      } catch (IOException e) {
        rentry.setError(new ErrorEntry(SYSTEM_FAILURE, "error encoding CRL"));
        return rentry;
      }
    }
    rentry.setCert(certInfo.getCert().getCert().getEncoded());
    return rentry;
  }

  protected SdkResponse confirmCertificates(X509Ca ca, byte[] request, String msgId) {
    ConfirmCertsRequest req = ConfirmCertsRequest.decode(request);
    String tid = req.getTransactionId();
    boolean successful = true;
    for (ConfirmCertRequestEntry m : req.getEntries()) {
      BigInteger certReqId = m.getCertReqId();
      byte[] certHash = m.getCerthash();
      CertificateInfo certInfo = pendingCertPool.removeCertificate(tid, certReqId, certHash);
      if (certInfo == null) {
        LOG.warn("no cert under transactionId={}, certReqId={} and certHash=0X{}",
            tid, certReqId, Hex.encode(certHash));
        continue;
      }

      if (m.isAccept()) {
        continue;
      }

      BigInteger serialNumber = certInfo.getCert().getCert().getSerialNumber();
      try {
        ca.revokeCert(serialNumber, CrlReason.CESSATION_OF_OPERATION, new Date(), msgId);
      } catch (OperationException ex) {
        LogUtil.warn(LOG, ex, "could not revoke certificate ca=" + ca.getCaInfo().getIdent()
            + " serialNumber=" + LogUtil.formatCsn(serialNumber));
      }

      successful = false;
    }

    // all other certificates should be revoked
    if (!revokePendingCertificates(ca, tid, msgId)) {
      successful = false;
    }

    if (successful) {
      return null;
    }

    return new ErrorResponse(tid, SYSTEM_FAILURE, null);
  } // method confirmCertificates

  public boolean revokePendingCertificates(X509Ca ca, String transactionId, String msgId) {
    Set<CertificateInfo> remainingCerts = pendingCertPool.removeCertificates(transactionId);

    if (CollectionUtil.isEmpty(remainingCerts)) {
      return true;
    }

    boolean successful = true;
    Date invalidityDate = new Date();
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

}
