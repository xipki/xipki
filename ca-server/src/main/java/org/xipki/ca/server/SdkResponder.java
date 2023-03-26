// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.api.profile.Certprofile;
import org.xipki.ca.sdk.*;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.security.CrlReason;
import org.xipki.security.X509Cert;
import org.xipki.security.util.HttpRequestMetadataRetriever;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;
import org.xipki.util.exception.InsufficientPermissionException;
import org.xipki.util.exception.OperationException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.xipki.ca.sdk.SdkConstants.*;
import static org.xipki.util.PermissionConstants.*;
import static org.xipki.util.exception.ErrorCode.*;

/**
 * SDK responder.
 *
 * @author Lijun Liao (xipki)
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

      Instant invalidityDate = Instant.now();
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
          ca.revokeCert(null, serialNumber, CrlReason.CESSATION_OF_OPERATION, invalidityDate);
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

  private static final Set<String> reenrollCertExtnIds;

  private final CaManagerImpl caManager;

  private ScheduledThreadPoolExecutor threadPoolExecutor;

  static {
    reenrollCertExtnIds = CollectionUtil.asUnmodifiableSet(
        Extension.biometricInfo.getId(),          Extension.extendedKeyUsage.getId(),
        Extension.keyUsage.getId(),               Extension.qCStatements.getId(),
        Extension.subjectAlternativeName.getId(), Extension.subjectInfoAccess.getId());
  }

  public SdkResponder(CaManagerImpl caManager) {
    this.caManager = Args.notNull(caManager, "caManager");
    this.pendingCertPool = new PendingCertificatePool();

    threadPoolExecutor = new ScheduledThreadPoolExecutor(1);
    threadPoolExecutor.setRemoveOnCancelPolicy(true);
    threadPoolExecutor.scheduleAtFixedRate(new PendingPoolCleaner(), 10, 10, TimeUnit.MINUTES);
  }

  public SdkResponse service(String path, byte[] request, HttpRequestMetadataRetriever httpRetriever) {
    try {
      SdkResponse resp = service0(path, request, httpRetriever);
      if (resp instanceof ErrorResponse) {
        LOG.warn("returned ErrorResponse: {}", resp);
      }
      return resp;
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      return new ErrorResponse(null, SYSTEM_FAILURE, "internal error");
    }
  }

  private SdkResponse service0(String path, byte[] request, HttpRequestMetadataRetriever httpRetriever) {
    try {
      if (caManager == null) {
        return new ErrorResponse(null, SYSTEM_FAILURE, "responderManager in servlet not configured");
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
          return new ErrorResponse(null, PATH_NOT_FOUND, "CA unknown");
        }
      }

      if (StringUtil.isBlank(command)) {
        return new ErrorResponse(null, PATH_NOT_FOUND, "command is not specified");
      }

      if (ca == null || ca.getCaInfo().getStatus() != CaStatus.ACTIVE) {
        String message = (ca == null) ? "unknown CA '" + caName + "'" : "CA '" + caName + "' is out of service";
        return new ErrorResponse(null, PATH_NOT_FOUND, message);
      }

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

      switch (command) {
        case CMD_health: {
          boolean healthy = ca.healthy();
          return healthy ? null : new ErrorResponse(null, SYSTEM_UNAVAILABLE, "CA is not healthy");
        }
        case CMD_cacert: {
          byte[][] certs = new byte[1][];
          certs[0] = ca.getCaInfo().getCert().getEncoded();
          CertChainResponse resp = new CertChainResponse();
          resp.setCertificates(certs);
          return resp;
        }
        case CMD_cacerts: {
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
          return enroll(ca, request, requestor, false, false);
        }
        case CMD_reenroll: {
          assertPermitted(requestor, REENROLL_CERT);
          return enroll(ca, request, requestor, true, false);
        }
        case CMD_enroll_cross: {
          assertPermitted(requestor, ENROLL_CROSS);
          return enroll(ca, request, requestor, false, true);
        }
        case CMD_poll_cert: {
          if (!(requestor.isPermitted(ENROLL_CERT) || requestor.isPermitted(REENROLL_CERT))) {
            throw new OperationException(NOT_PERMITTED);
          }
          return poll(ca, request);
        }
        case CMD_revoke_cert: {
          assertPermitted(requestor, REVOKE_CERT);
          return revoke(requestor, ca, request);
        }
        case CMD_confirm_enroll: {
          if (!(requestor.isPermitted(ENROLL_CERT) || requestor.isPermitted(REENROLL_CERT))) {
            throw new OperationException(NOT_PERMITTED);
          }
          return confirmCertificates(requestor, ca, request);
        }
        case CMD_revoke_pending_cert: {
          if (!(requestor.isPermitted(ENROLL_CERT) || requestor.isPermitted(REENROLL_CERT))) {
            throw new OperationException(NOT_PERMITTED);
          }
          TransactionIdRequest req = TransactionIdRequest.decode(request);
          revokePendingCertificates(requestor, ca, req.getTid());
          return null;
        }
        case CMD_unsuspend_cert:
        case CMD_remove_cert: {
          boolean unsuspend = CMD_unsuspend_cert.equals(command);
          assertPermitted(requestor, unsuspend ? UNSUSPEND_CERT : REMOVE_CERT);
          return removeOrUnsuspend(requestor, ca, request, unsuspend);
        }
        case CMD_gen_crl: {
          assertPermitted(requestor, GEN_CRL);
          return genCrl(requestor, ca, request);
        }
        case CMD_crl: {
          return getCrl(requestor, ca, request);
        }
        case CMD_get_cert: {
          assertPermitted(requestor, GET_CERT);
          return getCert(ca, request);
        }
        case CMD_profileinfo: {
          return getProfileInfo(request);
        }
        default: {
          return new ErrorResponse(null, PATH_NOT_FOUND, "invalid command '" + command + "'");
        }
      }
    } catch (OperationException ex) {
      return new ErrorResponse(null, ex.getErrorCode(), ex.getErrorMessage());
    }
  } // method service

  private SdkResponse enroll(X509Ca ca, byte[] request, RequestorInfo requestor, boolean reenroll, boolean crossCert)
      throws OperationException {
    EnrollCertsRequest req = EnrollCertsRequest.decode(request);
    List<EnrollCertRequestEntry> entries = req.getEntries();

    List<CertTemplateData> certTemplates = new ArrayList<>(req.getEntries().size());

    Set<String> profiles = new HashSet<>();

    for (EnrollCertRequestEntry entry : entries) {
      String profile = entry.getCertprofile();

      Long notBeforeInSec = entry.getNotBefore();
      Instant notBefore = (notBeforeInSec == null) ? null : Instant.ofEpochSecond(notBeforeInSec);

      Long notAfterInSec = entry.getNotAfter();
      Instant notAfter = (notAfterInSec == null) ? null : Instant.ofEpochSecond(notAfterInSec);

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
          if (!reenroll) {
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

        if (reenroll) {
          CertWithRevocationInfo oldCert;

          OldCertInfoByIssuerAndSerial ocIsn = entry.getOldCertIsn();
          OldCertInfoBySubject ocSubject = entry.getOldCertSubject();

          if (ocIsn == null && ocSubject == null) {
            throw new OperationException(BAD_CERT_TEMPLATE,  "Neither oldCertIsn nor oldCertSubject is specified" +
                " in reenroll_cert command, but exactly one of them is permitted");
          } else if (ocIsn != null && ocSubject != null) {
            throw new OperationException(BAD_CERT_TEMPLATE, "Both oldCertIsn and oldCertSubject are specified" +
                " in reenroll_cert command, but exactly one of them is permitted");
          }

          boolean reusePublicKey;
          String text;

          if (ocIsn != null) {
            reusePublicKey = ocIsn.isReusePublicKey();
            X500Name issuer = X500Name.getInstance(ocIsn.getIssuer());
            BigInteger serialNumber = ocIsn.getSerialNumber();

            text = "certificate with the issuer '" + X509Util.x500NameText(issuer) +
                    "' and serial number " + serialNumber;

            try {
              oldCert = ca.getCertWithRevocationInfo(serialNumber);
            } catch (CertificateException ex) {
              LogUtil.warn(LOG, ex, "error in ca.getCertWithRevocationInfo");
              throw new OperationException(SYSTEM_FAILURE, "error while finding " + text);
            }
          } else {
            reusePublicKey = ocSubject.isReusePublicKey();
            X500Name oldSubject = X500Name.getInstance(ocSubject.getSubject());
            String subjectText = X509Util.x500NameText(oldSubject);
            text = "certificate with subject '" + subjectText + "'";
            try {
              oldCert = ca.getCertWithRevocationInfoBySubject(oldSubject, ocSubject.getSan());
            } catch (CertificateException ex) {
              LogUtil.warn(LOG, ex, "error in ca.getCertWithRevocationInfoBySubject");
              throw new OperationException(SYSTEM_FAILURE, "error while finding " + text);
            }
          }

          if (oldCert == null) {
            throw new OperationException(UNKNOWN_CERT, "found no " + text);
          }

          if (oldCert.isRevoked()) {
            throw new OperationException(CERT_REVOKED, "could not update a revoked " + text);
          }

          if (profile == null) {
            profile = oldCert.getCertprofile();
            profiles.add(profile);
          }

          if (subject == null) {
            subject = oldCert.getCert().getCert().getSubject();
          }

          if (publicKeyInfo == null && reusePublicKey) {
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
            if (!(extns.containsKey(id) || reenrollCertExtnIds.contains(id))) {
              extns.put(id, oldExtensions.getExtension(oid));
            }
          }

          extensions = new Extensions(extns.values().toArray(new Extension[0]));
        }
      }

      profiles.add(profile);
      boolean serverkeygen = publicKeyInfo == null;
      CertTemplateData certTemplate = new CertTemplateData(subject, publicKeyInfo,
          notBefore, notAfter, extensions, profile, entry.getCertReqId(), serverkeygen);
      certTemplate.setForCrossCert(crossCert);
      certTemplates.add(certTemplate);
    }

    // check the profile
    for (String profile : profiles) {
      if (!requestor.isCertprofilePermitted(profile)) {
        throw new OperationException(NOT_PERMITTED, "cert profile " + profile + " is not allowed");
      }

      if (crossCert) {
        IdentifiedCertprofile idProfile = caManager.getIdentifiedCertprofile(profile);
        if (idProfile == null) {
          throw new OperationException(UNKNOWN_CERT_PROFILE, "unknown cert profile " + profile);
        }

        if (Certprofile.CertLevel.CROSS != idProfile.getCertLevel()) {
          throw new OperationException(BAD_CERT_TEMPLATE, "cert profile " + profile + " is not for CROSS certificate");
        }
      }
    }

    long waitForConfirmUtil = 0;
    boolean explicitConform = req.getExplicitConfirm() != null && req.getExplicitConfirm();

    if (explicitConform) {
      int confirmWaitTimeMs = req.getConfirmWaitTimeMs() == null
          ? DFLT_CONFIRM_WAIT_TIME_MS : req.getConfirmWaitTimeMs();
      waitForConfirmUtil = Clock.systemUTC().millis() + confirmWaitTimeMs;
    }

    List<EnrollOrPullCertResponseEntry> rentries =
        generateCertificates(requestor, ca, certTemplates, req, waitForConfirmUtil);
    if (rentries == null) {
      return new ErrorResponse(req.getTransactionId(), SYSTEM_FAILURE, null);
    } else {
      EnrollOrPollCertsResponse resp = new EnrollOrPollCertsResponse();
      resp.setTransactionId(req.getTransactionId());

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

      return resp;
    }
  } // enroll

  private SdkResponse poll(X509Ca ca, byte[] request) throws OperationException {
    PollCertRequest req = PollCertRequest.decode(request);
    assertIssuerMatch(ca, req.getIssuer(), req.getAuthorityKeyIdentifier(), req.getIssuerCertSha1Fp());

    String tid = req.getTransactionId();

    List<EnrollOrPullCertResponseEntry> rentries = new ArrayList<>(req.getEntries().size());
    for (PollCertRequestEntry m : req.getEntries()) {
      EnrollOrPullCertResponseEntry rentry = new EnrollOrPullCertResponseEntry();
      rentry.setId(m.getId());

      X500Name subject;
      try {
        subject = m.getSubject().toX500Name();
      } catch (IOException e) {
        rentry.setError(new ErrorEntry(BAD_REQUEST, "invalid subject"));
        continue;
      }

      X509Cert cert = ca.getCert(subject, tid);
      if (cert != null) {
        rentry.setCert(cert.getEncoded());
        rentries.add(rentry);
      } else {
        rentry.setError(new ErrorEntry(UNKNOWN_CERT, null));
      }
    }

    EnrollOrPollCertsResponse resp = new EnrollOrPollCertsResponse();
    resp.setTransactionId(tid);
    resp.setEntries(rentries);
    return resp;
  }

  private SdkResponse revoke(RequestorInfo requestor, X509Ca ca, byte[] request)
      throws OperationException {
    RevokeCertsRequest req = RevokeCertsRequest.decode(request);
    assertIssuerMatch(ca, req);

    List<RevokeCertRequestEntry> entries = req.getEntries();
    List<SingleCertSerialEntry> rentries = new ArrayList<>(entries.size());
    for (RevokeCertRequestEntry entry : entries) {
      BigInteger serialNumber = entry.getSerialNumber();
      SingleCertSerialEntry rentry = new SingleCertSerialEntry();
      rentries.add(rentry);

      rentry.setSerialNumber(serialNumber);
      CrlReason reason = entry.getReason();

      if (reason == CrlReason.REMOVE_FROM_CRL) {
        String msg = "Reason removeFromCRL is not permitted";
        rentry.setError(new ErrorEntry(BAD_REQUEST, msg));
      } else {
        Instant invalidityTime = entry.getInvalidityTime() == null
            ? null : Instant.ofEpochSecond(entry.getInvalidityTime());
        try {
          ca.revokeCert(requestor, serialNumber, reason, invalidityTime);
        } catch (OperationException e) {
          String msg = e.getErrorMessage();
          rentry.setError(new ErrorEntry(e.getErrorCode(), msg));
        }
      }
    }
    RevokeCertsResponse resp = new RevokeCertsResponse();
    resp.setEntries(rentries);
    return resp;
  }

  private SdkResponse removeOrUnsuspend(RequestorInfo requestor, X509Ca ca, byte[] request, boolean unsuspend)
      throws OperationException {
    UnsuspendOrRemoveRequest req = UnsuspendOrRemoveRequest.decode(request);
    assertIssuerMatch(ca, req);

    List<BigInteger> entries = req.getEntries();
    List<SingleCertSerialEntry> rentries = new ArrayList<>(req.getEntries().size());

    for (BigInteger serialNumber : entries) {
      SingleCertSerialEntry rentry = new SingleCertSerialEntry();
      rentry.setSerialNumber(serialNumber);
      rentries.add(rentry);
      try {
        if (unsuspend) {
          ca.unsuspendCert(requestor, serialNumber);
        } else {
          ca.removeCert(requestor,serialNumber);
        }
      } catch (OperationException e) {
        rentry.setError(new ErrorEntry(e.getErrorCode(), e.getErrorMessage()));
      }
    }

    UnSuspendOrRemoveCertsResponse resp = new UnSuspendOrRemoveCertsResponse();
    resp.setEntries(rentries);
    return resp;
  }

  private void assertIssuerMatch(X509Ca ca, ChangeCertStatusRequest req) throws OperationException {
    assertIssuerMatch(ca, req.getIssuer(), req.getAuthorityKeyIdentifier(), req.getIssuerCertSha1Fp());
  }

  private void assertIssuerMatch(X509Ca ca, X500NameType issuer, byte[] authorityKeyId, byte[] issuerCertSha1Fp)
      throws OperationException {
    if (issuer == null && authorityKeyId == null && issuerCertSha1Fp == null) {
      throw new OperationException(BAD_REQUEST, "no issuer's identifier is specified");
    }

    if (issuer != null) {
      X500Name x500Issuer;
      try {
        x500Issuer = issuer.toX500Name();
      } catch (IOException e) {
        throw new OperationException(BAD_REQUEST, "error toX500Name");
      }

      X500Name caSubject = ca.getCaCert().getSubject();
      if (!x500Issuer.equals(caSubject)) {
        throw new OperationException(BAD_CERT_TEMPLATE, "issuer does not target at the CA");
      }
    }

    if (authorityKeyId != null) {
      byte[] caSki = ca.getCaCert().getSubjectKeyId();
      if (!Arrays.equals(caSki, authorityKeyId)) {
        throw new OperationException(BAD_CERT_TEMPLATE, "AuthorityKeyIdentifier does not target at the CA");
      }
    }

    if (issuerCertSha1Fp != null) {
      if (!Hex.encode(issuerCertSha1Fp).equalsIgnoreCase(ca.getHexSha1OfCert())) {
        throw new OperationException(BAD_CERT_TEMPLATE, "IssuerCertSha256Fp does not target at the CA");
      }
    }
  }

  private SdkResponse genCrl(RequestorInfo requestor, X509Ca ca, byte[] request) throws OperationException {
    GenCRLRequest req = GenCRLRequest.decode(request);
    // TODO: consider req
    X509CRLHolder crl = ca.generateCrlOnDemand(requestor);
    return buildCrlResp(crl, "generate CRL");
  }

  private SdkResponse getCrl(RequestorInfo requestor, X509Ca ca, byte[] request) throws OperationException {
    GetCRLRequest req = GetCRLRequest.decode(request);
    X509CRLHolder crl = ca.getCrl(requestor, req.getCrlNumber());
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

  private SdkResponse getCert(X509Ca ca, byte[] request) throws OperationException {
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

  private SdkResponse getProfileInfo(byte[] request)
      throws OperationException {
    CertprofileInfoRequest req = CertprofileInfoRequest.decode(request);
    String profileName = req.getProfile();
    return caManager.getCertprofileInfo(profileName);
  }

  private static void assertPermitted(RequestorInfo requestor, int permission) throws OperationException {
    try {
      requestor.assertPermitted(permission);
    } catch (InsufficientPermissionException ex) {
      throw new OperationException(NOT_PERMITTED, ex.getMessage());
    }
  }

  private List<EnrollOrPullCertResponseEntry> generateCertificates(
      RequestorInfo requestor, X509Ca ca, List<CertTemplateData> certTemplates,
      EnrollCertsRequest req, long waitForConfirmUtil) {
    String caName = ca.getCaInfo().getIdent().getName();
    final int n = certTemplates.size();
    String tid = req.getTransactionId();
    Boolean b = req.getGroupEnroll();
    boolean groupEnroll = b != null && b;

    b = req.getExplicitConfirm();
    boolean explicitConfirm = b != null && b;

    List<EnrollOrPullCertResponseEntry> ret = new ArrayList<>(n);

    if (groupEnroll) {
      List<CertificateInfo> certInfos = null;
      try {
        certInfos = ca.generateCerts(requestor, certTemplates, tid);

        for (int i = 0; i < n; i++) {
          CertificateInfo certInfo = certInfos.get(i);

          BigInteger certReqId = certTemplates.get(i).getCertReqId();
          if (explicitConfirm) {
            pendingCertPool.addCertificate(tid, certReqId, certInfo, waitForConfirmUtil);
          }

          EnrollOrPullCertResponseEntry rentry = new EnrollOrPullCertResponseEntry();
          rentry.setId(certReqId);
          fillResponseEntry(rentry, certInfo);
          ret.add(rentry);
        }

        return ret;
      } catch (OperationException ex) {
        if (certInfos != null) {
          for (CertificateInfo certInfo : certInfos) {
            BigInteger sn = certInfo.getCert().getCert().getSerialNumber();
            try {
              ca.revokeCert(requestor, sn, CrlReason.CESSATION_OF_OPERATION, null);
            } catch (OperationException ex2) {
              LogUtil.error(LOG, ex2, "CA " + caName + " could not revoke certificate " + sn);
            }
          }
        }
        return null;
      }
    }

    Long reqDbId = null;
    boolean savingRequestFailed = false;

    EnrollOrPullCertResponseEntry rentry = new EnrollOrPullCertResponseEntry();

    for (CertTemplateData certTemplate : certTemplates) {
      BigInteger certReqId = certTemplate.getCertReqId();
      rentry.setId(certReqId);

      CertificateInfo certInfo;
      try {
        certInfo = ca.generateCert(requestor, certTemplate, tid);

        if (explicitConfirm) {
          pendingCertPool.addCertificate(tid, certReqId, certInfo, waitForConfirmUtil);
        }

        fillResponseEntry(rentry, certInfo);
      } catch (OperationException ex) {
        rentry.setError(new ErrorEntry(ex.getErrorCode(), ex.getErrorMessage()));
      }

      ret.add(rentry);
    }

    return ret;
  } // method generateCertificates

  private static void fillResponseEntry(EnrollOrPullCertResponseEntry rentry, CertificateInfo certInfo) {
    if (certInfo.getPrivateKey() != null) {
      try {
        rentry.setPrivateKey(certInfo.getPrivateKey().getEncoded());
      } catch (IOException e) {
        rentry.setError(new ErrorEntry(SYSTEM_FAILURE, "error encoding CRL"));
        return;
      }
    }
    rentry.setCert(certInfo.getCert().getCert().getEncoded());
  }

  protected SdkResponse confirmCertificates(RequestorInfo requestor, X509Ca ca, byte[] request) {
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
        ca.revokeCert(requestor, serialNumber, CrlReason.CESSATION_OF_OPERATION, Instant.now());
      } catch (OperationException ex) {
        LogUtil.warn(LOG, ex, "could not revoke certificate ca=" + ca.getCaInfo().getIdent()
            + " serialNumber=" + LogUtil.formatCsn(serialNumber));
      }

      successful = false;
    }

    // all other certificates should be revoked
    if (!revokePendingCertificates(requestor, ca, tid)) {
      successful = false;
    }

    if (successful) {
      return null;
    }

    return new ErrorResponse(tid, SYSTEM_FAILURE, null);
  } // method confirmCertificates

  public boolean revokePendingCertificates(RequestorInfo requestor, X509Ca ca, String transactionId) {
    Set<CertificateInfo> remainingCerts = pendingCertPool.removeCertificates(transactionId);

    if (CollectionUtil.isEmpty(remainingCerts)) {
      return true;
    }

    boolean successful = true;
    Instant invalidityDate = Instant.now();
    for (CertificateInfo remainingCert : remainingCerts) {
      try {
        ca.revokeCert(requestor, remainingCert.getCert().getCert().getSerialNumber(),
            CrlReason.CESSATION_OF_OPERATION, invalidityDate);
      } catch (OperationException ex) {
        successful = false;
      }
    }

    return successful;
  } // method revokePendingCertificates

  public void close() {
    if (threadPoolExecutor == null) {
      return;
    }
    threadPoolExecutor.shutdown();
    threadPoolExecutor = null;
  }

}
