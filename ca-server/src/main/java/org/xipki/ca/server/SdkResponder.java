// Copyright (c) 2013-2024 xipki. All rights reserved.
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
import org.xipki.ca.sdk.CaIdentifierRequest;
import org.xipki.ca.sdk.CaNameResponse;
import org.xipki.ca.sdk.CertChainResponse;
import org.xipki.ca.sdk.CertprofileInfoRequest;
import org.xipki.ca.sdk.CertsMode;
import org.xipki.ca.sdk.ConfirmCertsRequest;
import org.xipki.ca.sdk.CrlResponse;
import org.xipki.ca.sdk.EnrollCertsRequest;
import org.xipki.ca.sdk.EnrollOrPollCertsResponse;
import org.xipki.ca.sdk.ErrorEntry;
import org.xipki.ca.sdk.ErrorResponse;
import org.xipki.ca.sdk.GenCRLRequest;
import org.xipki.ca.sdk.GetCRLRequest;
import org.xipki.ca.sdk.GetCertRequest;
import org.xipki.ca.sdk.OldCertInfo;
import org.xipki.ca.sdk.PayloadResponse;
import org.xipki.ca.sdk.PollCertRequest;
import org.xipki.ca.sdk.RevokeCertsRequest;
import org.xipki.ca.sdk.RevokeCertsResponse;
import org.xipki.ca.sdk.SdkResponse;
import org.xipki.ca.sdk.SingleCertSerialEntry;
import org.xipki.ca.sdk.TransactionIdRequest;
import org.xipki.ca.sdk.UnSuspendOrRemoveCertsResponse;
import org.xipki.ca.sdk.UnsuspendOrRemoveCertsRequest;
import org.xipki.ca.sdk.X500NameType;
import org.xipki.ca.server.mgmt.CaManagerImpl;
import org.xipki.pki.ErrorCode;
import org.xipki.pki.OperationException;
import org.xipki.security.CrlReason;
import org.xipki.security.X509Cert;
import org.xipki.security.util.TlsHelper;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.Hex;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.InsufficientPermissionException;
import org.xipki.util.http.XiHttpRequest;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.xipki.ca.api.mgmt.PermissionConstants.ENROLL_CERT;
import static org.xipki.ca.api.mgmt.PermissionConstants.ENROLL_CROSS;
import static org.xipki.ca.api.mgmt.PermissionConstants.GEN_CRL;
import static org.xipki.ca.api.mgmt.PermissionConstants.GET_CERT;
import static org.xipki.ca.api.mgmt.PermissionConstants.REENROLL_CERT;
import static org.xipki.ca.api.mgmt.PermissionConstants.REMOVE_CERT;
import static org.xipki.ca.api.mgmt.PermissionConstants.REVOKE_CERT;
import static org.xipki.ca.api.mgmt.PermissionConstants.UNSUSPEND_CERT;
import static org.xipki.ca.sdk.SdkConstants.CMD_cacert;
import static org.xipki.ca.sdk.SdkConstants.CMD_cacert2;
import static org.xipki.ca.sdk.SdkConstants.CMD_cacerts;
import static org.xipki.ca.sdk.SdkConstants.CMD_cacerts2;
import static org.xipki.ca.sdk.SdkConstants.CMD_caname;
import static org.xipki.ca.sdk.SdkConstants.CMD_confirm_enroll;
import static org.xipki.ca.sdk.SdkConstants.CMD_crl;
import static org.xipki.ca.sdk.SdkConstants.CMD_enroll;
import static org.xipki.ca.sdk.SdkConstants.CMD_enroll_cross;
import static org.xipki.ca.sdk.SdkConstants.CMD_gen_crl;
import static org.xipki.ca.sdk.SdkConstants.CMD_get_cert;
import static org.xipki.ca.sdk.SdkConstants.CMD_health;
import static org.xipki.ca.sdk.SdkConstants.CMD_poll_cert;
import static org.xipki.ca.sdk.SdkConstants.CMD_profileinfo;
import static org.xipki.ca.sdk.SdkConstants.CMD_reenroll;
import static org.xipki.ca.sdk.SdkConstants.CMD_remove_cert;
import static org.xipki.ca.sdk.SdkConstants.CMD_revoke_cert;
import static org.xipki.ca.sdk.SdkConstants.CMD_revoke_pending_cert;
import static org.xipki.ca.sdk.SdkConstants.CMD_unsuspend_cert;
import static org.xipki.pki.ErrorCode.BAD_CERT_TEMPLATE;
import static org.xipki.pki.ErrorCode.BAD_REQUEST;
import static org.xipki.pki.ErrorCode.CERT_REVOKED;
import static org.xipki.pki.ErrorCode.NOT_PERMITTED;
import static org.xipki.pki.ErrorCode.PATH_NOT_FOUND;
import static org.xipki.pki.ErrorCode.SYSTEM_FAILURE;
import static org.xipki.pki.ErrorCode.SYSTEM_UNAVAILABLE;
import static org.xipki.pki.ErrorCode.UNAUTHORIZED;
import static org.xipki.pki.ErrorCode.UNKNOWN_CERT;
import static org.xipki.pki.ErrorCode.UNKNOWN_CERT_PROFILE;

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

  private final String reverseProxyMode;

  private final CaManagerImpl caManager;

  private ScheduledThreadPoolExecutor threadPoolExecutor;

  static {
    reenrollCertExtnIds = CollectionUtil.asUnmodifiableSet(
        Extension.biometricInfo.getId(),          Extension.extendedKeyUsage.getId(),
        Extension.keyUsage.getId(),               Extension.qCStatements.getId(),
        Extension.subjectAlternativeName.getId(), Extension.subjectInfoAccess.getId());
  }

  public SdkResponder(String reverseProxyMode, CaManagerImpl caManager) {
    this.reverseProxyMode = reverseProxyMode;
    this.caManager = Args.notNull(caManager, "caManager");
    this.pendingCertPool = new PendingCertificatePool();

    threadPoolExecutor = new ScheduledThreadPoolExecutor(1);
    threadPoolExecutor.setRemoveOnCancelPolicy(true);
    threadPoolExecutor.scheduleAtFixedRate(new PendingPoolCleaner(), 10, 10, TimeUnit.MINUTES);
  }

  public SdkResponse service(String path, byte[] request, XiHttpRequest httpRequest) {
    try {
      SdkResponse resp = service0(path, request, httpRequest);
      if (resp instanceof ErrorResponse) {
        LOG.warn("returned ErrorResponse: {}", resp);
      }
      return resp;
    } catch (Throwable th) {
      LOG.error("Throwable thrown, this should not happen!", th);
      return new ErrorResponse(null, SYSTEM_FAILURE, "internal error");
    }
  }

  private SdkResponse service0(String path, byte[] request, XiHttpRequest httpRequest) {
    try {
      if (caManager == null) {
        return new ErrorResponse(null, SYSTEM_FAILURE, "responderManager in servlet not configured");
      }

      String caName = null;
      String command = null;

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

        if ("-".equals(caAlias)) {
          caName = "-";
        } else {
          caName = caManager.getCaNameForAlias(caAlias);
          if (caName == null) {
            caName = caAlias;
          }
        }
      }

      if (StringUtil.isBlank(command)) {
        return new ErrorResponse(null, PATH_NOT_FOUND, "command is not specified");
      }

      CaIdentifierRequest req = null;

      // get the CA instance
      X509Ca ca;
      if (!"-".equals(caName)) {
        try {
          ca = caManager.getX509Ca(caName);
        } catch (CaMgmtException e) {
          return new ErrorResponse(null, PATH_NOT_FOUND, "CA unknown");
        }

        if (ca == null) {
          return new ErrorResponse(null, PATH_NOT_FOUND, "unknown CA '" + caName + "'");
        }
      } else {
        switch (command) {
          case CMD_caname:
          case CMD_cacert2:
          case CMD_cacerts2: {
            req = CaIdentifierRequest.decode(requireNonNullRequest(request));
            break;
          }
          case CMD_poll_cert:
          case CMD_remove_cert:
          case CMD_revoke_cert:
          case CMD_unsuspend_cert: {
            if (CMD_poll_cert.equals(command)) {
              req = PollCertRequest.decode(requireNonNullRequest(request));
            } else if (CMD_revoke_cert.equals(command)) {
              req = RevokeCertsRequest.decode(requireNonNullRequest(request));
            } else {
              req = UnsuspendOrRemoveCertsRequest.decode(requireNonNullRequest(request));
            }
            break;
          }
          default:
            return new ErrorResponse(null, PATH_NOT_FOUND, "invalid command '" + command + "'");
        }

        ca = caManager.getCa(req);
        if (ca == null) {
          String message = "could not find CA for " + req.idText();
          return new ErrorResponse(null, PATH_NOT_FOUND, message);
        }
      }

      if (ca.getCaInfo().getStatus() != CaStatus.active) {
        return new ErrorResponse(null, PATH_NOT_FOUND,
            "CA '" + ca.getCaIdent().getName() + "' is out of service");
      }

      X509Cert clientCert;
      try {
        clientCert = TlsHelper.getTlsClientCert(httpRequest, reverseProxyMode);
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
        case CMD_health:
          return ca.healthy() ? null : new ErrorResponse(null, SYSTEM_UNAVAILABLE, "CA is not healthy");
        case CMD_cacert:
          return buildCertChainResponse(ca.getCaInfo().getCert(), null);
        case CMD_cacerts:
          return buildCertChainResponse(ca.getCaInfo().getCert(), ca.getCaInfo().getCertchain());
        case CMD_enroll:
          assertPermitted(requestor, ENROLL_CERT);
          return enroll(ca, requireNonNullRequest(request), requestor, false, false);
        case CMD_reenroll:
          assertPermitted(requestor, REENROLL_CERT);
          return enroll(ca, requireNonNullRequest(request), requestor, true, false);
        case CMD_enroll_cross:
          assertPermitted(requestor, ENROLL_CROSS);
          return enroll(ca, requireNonNullRequest(request), requestor, false, true);
        case CMD_poll_cert:
          if (!(requestor.isPermitted(ENROLL_CERT) || requestor.isPermitted(REENROLL_CERT))) {
            throw new OperationException(NOT_PERMITTED);
          }
          return poll(ca, (PollCertRequest) req, "-".equals(caName));
        case CMD_revoke_cert:
          assertPermitted(requestor, REVOKE_CERT);
          return revoke(requestor, ca, (RevokeCertsRequest) req, "-".equals(caName));
        case CMD_confirm_enroll:
          if (!(requestor.isPermitted(ENROLL_CERT) || requestor.isPermitted(REENROLL_CERT))) {
            throw new OperationException(NOT_PERMITTED);
          }
          return confirmCertificates(requestor, ca, requireNonNullRequest(request));
        case CMD_revoke_pending_cert:
          if (!(requestor.isPermitted(ENROLL_CERT) || requestor.isPermitted(REENROLL_CERT))) {
            throw new OperationException(NOT_PERMITTED);
          }
          revokePendingCertificates(requestor, ca,
              TransactionIdRequest.decode(requireNonNullRequest(request)).getTid());
          return null;
        case CMD_unsuspend_cert:
          assertPermitted(requestor, UNSUSPEND_CERT);
          return removeOrUnsuspend(requestor, ca, (UnsuspendOrRemoveCertsRequest) req, true, "-".equals(caName));
        case CMD_remove_cert:
          assertPermitted(requestor, REMOVE_CERT);
          return removeOrUnsuspend(requestor, ca, (UnsuspendOrRemoveCertsRequest) req, false, "-".equals(caName));
        case CMD_gen_crl:
          assertPermitted(requestor, GEN_CRL);
          return genCrl(requestor, ca, requireNonNullRequest(request));
        case CMD_crl:
          return getCrl(requestor, ca, requireNonNullRequest(request));
        case CMD_get_cert:
          assertPermitted(requestor, GET_CERT);
          return getCert(ca, requireNonNullRequest(request));
        case CMD_profileinfo:
          return getProfileInfo(requireNonNullRequest(request));
        case CMD_cacert2:
          return buildCertChainResponse(ca.getCaCert(), null);
        case CMD_cacerts2:
          return buildCertChainResponse(ca.getCaCert(), ca.caInfo.getCertchain());
        case CMD_caname:
          String name = ca.getCaIdent().getName();
          Set<String> aliases = caManager.getAliasesForCa(name);
          String[] aliasArray = CollectionUtil.isEmpty(aliases) ? null : aliases.toArray(new String[0]);
          return new CaNameResponse(name, aliasArray);
        default:
          return new ErrorResponse(null, PATH_NOT_FOUND, "invalid command '" + command + "'");
      }
    } catch (DecodeException ex) {
      return new ErrorResponse(null, BAD_REQUEST, ex.getMessage());
    } catch (OperationException ex) {
      return new ErrorResponse(null, ex.getErrorCode(), ex.getErrorMessage());
    }
  } // method service

  private static byte[] requireNonNullRequest(byte[] reqBytes) throws DecodeException {
    return Optional.ofNullable(reqBytes).orElseThrow(
        () -> new DecodeException("request must no be null"));
  }

  private CertChainResponse buildCertChainResponse(X509Cert cert, List<X509Cert> certchain) {
    int size = 1 + (certchain == null ? 0 : certchain.size());
    byte[][] certs = new byte[size][];
    certs[0] = cert.getEncoded();
    if (size > 1) {
      for (int i = 1; i < size; i++) {
        certs[i] = certchain.get(i - 1).getEncoded();
      }
    }

    return new CertChainResponse(certs);
  }

  private SdkResponse enroll(X509Ca ca, byte[] request, RequestorInfo requestor, boolean reenroll, boolean crossCert)
      throws OperationException, DecodeException {
    EnrollCertsRequest req = EnrollCertsRequest.decode(request);
    EnrollCertsRequest.Entry[] entries = req.getEntries();

    List<CertTemplateData> certTemplates = new ArrayList<>(entries.length);

    Set<String> profiles = new HashSet<>();

    for (EnrollCertsRequest.Entry entry : entries) {
      String profile = entry.getCertprofile();
      Instant notBefore = entry.getNotBefore();
      Instant notAfter = entry.getNotAfter();

      X500Name subject = null;
      Extensions extensions = null;
      SubjectPublicKeyInfo publicKeyInfo = null;

      if (entry.getP10req() != null) {
        // The PKCS#10 will only be used for transport of public key, subject and extensions.
        // The verification of POP is skipped here.
        CertificationRequestInfo certTemp;
        try {
          certTemp = CertificationRequest.getInstance(X509Util.toDerEncoded(entry.getP10req()))
                      .getCertificationRequestInfo();
        } catch (Exception ex) {
          throw new OperationException(ErrorCode.BAD_REQUEST, "invalid CSR: " + ex.getMessage());
        }
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
          OldCertInfo oldCertInfo = entry.getOldCertInfo();

          if (oldCertInfo == null) {
            throw new OperationException(BAD_CERT_TEMPLATE, "Neither oldCertIsn nor oldCertSubject is specified" +
                " in reenroll_cert command, but exactly one of them is permitted");
          }

          boolean reusePublicKey = oldCertInfo.isReusePublicKey();
          String text;
          CertWithRevocationInfo oldCert;

          if (oldCertInfo.getIsn() != null) {
            OldCertInfo.ByIssuerAndSerial ocIsn = oldCertInfo.getIsn();
            String issuer;
            try {
              issuer = X509Util.x500NameText(ocIsn.getIssuer().toX500Name());
            } catch (IOException ex) {
              throw new OperationException(BAD_CERT_TEMPLATE, "Invalid oldIsn.issuer: " + ex.getMessage());
            }
            if (!issuer.equals(ca.getCaCert().getSubjectText())) {
              throw new OperationException(UNKNOWN_CERT, "unknown issuer " + issuer);
            }

            BigInteger serialNumber = ocIsn.getSerialNumber();
            text = "certificate with the issuer '" + issuer + "' and serial number " + serialNumber;
            oldCert = ca.getCertWithRevocationInfo(serialNumber);
          } else if (oldCertInfo.getFsn() != null) {
            OldCertInfo.BySha1FpAndSerial ocFsn = oldCertInfo.getFsn();
            String sha1Fp = Hex.encode(ocFsn.getCaCertSha1());
            if (!sha1Fp.equalsIgnoreCase(ca.getHexSha1OfCert())) {
              throw new OperationException(UNKNOWN_CERT, "unknown issuer sha1fp" + sha1Fp);
            }

            BigInteger serialNumber = ocFsn.getSerialNumber();
            text = "certificate with the issuer (sha1fp) '" + sha1Fp + "' and serial number " + serialNumber;
            oldCert = ca.getCertWithRevocationInfo(serialNumber);
          } else {
            OldCertInfo.BySubject ocSubject = oldCertInfo.getSubject();
            X500Name oldSubject = X500Name.getInstance(ocSubject.getSubject());
            String subjectText = X509Util.x500NameText(oldSubject);
            text = "certificate with subject '" + subjectText + "'";
            oldCert = ca.getCertWithRevocationInfoBySubject(oldSubject, ocSubject.getSan());
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

      if (profile == null) {
        throw new OperationException(UNKNOWN_CERT_PROFILE, "cert profile is not set");
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
        IdentifiedCertprofile idProfile = Optional.ofNullable(caManager.getIdentifiedCertprofile(profile))
            .orElseThrow(() -> new OperationException(UNKNOWN_CERT_PROFILE, "unknown cert profile " + profile));

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

    EnrollOrPollCertsResponse.Entry[] rentries =
        generateCertificates(requestor, ca, certTemplates, req, waitForConfirmUtil);
    if (rentries == null) {
      return new ErrorResponse(req.getTransactionId(), SYSTEM_FAILURE, null);
    }

    EnrollOrPollCertsResponse resp = new EnrollOrPollCertsResponse();
    resp.setTransactionId(req.getTransactionId());

    resp.setEntries(rentries);
    if (explicitConform) {
      resp.setConfirmWaitTime(waitForConfirmUtil);
    }

    CertsMode caCertMode = req.getCaCertMode();
    if (caCertMode == CertsMode.CERT) {
      resp.setExtraCerts(new byte[][] {ca.getCaCert().getEncoded()});
    } else if (caCertMode == CertsMode.CHAIN) {
      List<X509Cert> chain = ca.getCaInfo().getCertchain();
      if (CollectionUtil.isEmpty(chain)) {
        resp.setExtraCerts(new byte[][] {ca.getCaCert().getEncoded()});
      } else {
        resp.setExtraCerts(ca.getEncodedCaCertChain().toArray(new byte[0][0]));
      }
    }

    return resp;
  } // enroll

  private SdkResponse poll(X509Ca ca, PollCertRequest req, boolean caReqMatchChecked) throws OperationException {
    if (!caReqMatchChecked) {
      assertIssuerMatch(ca, req);
    }

    String tid = req.getTransactionId();

    PollCertRequest.Entry[] entries = req.getEntries();
    EnrollOrPollCertsResponse.Entry[] rentries = new EnrollOrPollCertsResponse.Entry[entries.length];

    for (int i = 0; i < entries.length; i++) {
      PollCertRequest.Entry m = entries[i];

      ErrorEntry error = null;
      X500Name subject = null;
      try {
        subject = m.getSubject().toX500Name();
      } catch (IOException e) {
        error = new ErrorEntry(BAD_REQUEST, "invalid subject");
      }

      byte[] certBytes = null;
      if (error == null) {
        X509Cert cert = ca.getCert(subject, tid);
        if (cert != null) {
          certBytes = cert.getEncoded();
        } else {
          error = new ErrorEntry(UNKNOWN_CERT, null);
        }
      }

      rentries[i] = new EnrollOrPollCertsResponse.Entry(m.getId(), error, certBytes, null);
    }

    EnrollOrPollCertsResponse resp = new EnrollOrPollCertsResponse();
    resp.setTransactionId(tid);
    resp.setEntries(rentries);
    return resp;
  }

  private SdkResponse revoke(RequestorInfo requestor, X509Ca ca, RevokeCertsRequest req,
                             boolean caReqMatchChecked)
      throws OperationException {
    if (!caReqMatchChecked) {
      assertIssuerMatch(ca, req);
    }

    RevokeCertsRequest.Entry[] entries = req.getEntries();
    SingleCertSerialEntry[] rentries = new SingleCertSerialEntry[entries.length];
    for (int i = 0; i < entries.length; i++) {
      RevokeCertsRequest.Entry entry = entries[i];

      BigInteger serialNumber = entry.getSerialNumber();
      CrlReason reason = entry.getReason();

      ErrorEntry errorEntry = null;
      if (reason == CrlReason.REMOVE_FROM_CRL) {
        String msg = "Reason removeFromCRL is not permitted";
        errorEntry = new ErrorEntry(BAD_REQUEST, msg);
      } else {
        Instant invalidityTime = entry.getInvalidityTime();
        try {
          ca.revokeCert(requestor, serialNumber, reason, invalidityTime);
        } catch (OperationException e) {
          errorEntry = new ErrorEntry(e.getErrorCode(), e.getErrorMessage());
        }
      }

      rentries[i] = new SingleCertSerialEntry(serialNumber, errorEntry);
    }
    return new RevokeCertsResponse(rentries);
  }

  private SdkResponse removeOrUnsuspend(RequestorInfo requestor, X509Ca ca,
                                        UnsuspendOrRemoveCertsRequest req, boolean unsuspend, boolean caReqMatchChecked)
      throws OperationException {
    if (!caReqMatchChecked) {
      assertIssuerMatch(ca, req);
    }

    BigInteger[] entries = req.getEntries();
    SingleCertSerialEntry[] rentries = new SingleCertSerialEntry[entries.length];

    for (int i = 0; i < entries.length; i++) {
      BigInteger serialNumber = entries[i];
      ErrorEntry error = null;

      try {
        if (unsuspend) {
          ca.unsuspendCert(requestor, serialNumber);
        } else {
          ca.removeCert(requestor,serialNumber);
        }
      } catch (OperationException e) {
        error = new ErrorEntry(e.getErrorCode(), e.getErrorMessage());
      }

      rentries[i] = new SingleCertSerialEntry(serialNumber, error);
    }

    return new UnSuspendOrRemoveCertsResponse(rentries);
  }

  private void assertIssuerMatch(X509Ca ca, CaIdentifierRequest req) throws OperationException {
    X500NameType issuer = req.getIssuer();
    byte[] authorityKeyId = req.getAuthorityKeyIdentifier();
    byte[] issuerCertSha1Fp = req.getIssuerCertSha1Fp();

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

  private SdkResponse genCrl(RequestorInfo requestor, X509Ca ca, byte[] request)
      throws OperationException, DecodeException {
    GenCRLRequest req = GenCRLRequest.decode(request);
    // TODO: consider req
    X509CRLHolder crl = ca.generateCrlOnDemand(requestor);
    return buildCrlResp(crl, "generate CRL");
  }

  private SdkResponse getCrl(RequestorInfo requestor, X509Ca ca, byte[] request)
      throws OperationException, DecodeException {
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
      return new CrlResponse(crl.getEncoded());
    } catch (IOException e) {
      return new ErrorResponse(null, SYSTEM_FAILURE, "error encoding CRL");
    }
  }

  private SdkResponse getCert(X509Ca ca, byte[] request) throws OperationException, DecodeException {
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
    X509Cert cert = ca.getCert(sn);
    if (cert == null) {
      throw new OperationException(UNKNOWN_CERT, "unknown certificate");
    }
    return new PayloadResponse(cert.getEncoded());
  }

  private SdkResponse getProfileInfo(byte[] request)
      throws OperationException, DecodeException {
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

  private EnrollOrPollCertsResponse.Entry[] generateCertificates(
      RequestorInfo requestor, X509Ca ca, List<CertTemplateData> certTemplates,
      EnrollCertsRequest req, long waitForConfirmUtil) {
    String caName = ca.getCaInfo().getIdent().getName();
    final int n = certTemplates.size();
    String tid = req.getTransactionId();
    Boolean b = req.getGroupEnroll();
    boolean groupEnroll = b != null && b;

    b = req.getExplicitConfirm();
    boolean explicitConfirm = b != null && b;

    List<EnrollOrPollCertsResponse.Entry> ret = new ArrayList<>(n);

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

          byte[] privateKeyBytes = null;
          ErrorEntry error = null;
          if (certInfo.getPrivateKey() != null) {
            try {
              privateKeyBytes = certInfo.getPrivateKey().getEncoded();
            } catch (IOException e) {
              error = new ErrorEntry(SYSTEM_FAILURE, "error encoding CRL");
            }
          }

          byte[] certBytes = null;
          if (error == null) {
            certBytes = certInfo.getCert().getCert().getEncoded();
          }

          ret.add(new EnrollOrPollCertsResponse.Entry(certReqId, error, certBytes, privateKeyBytes));
        }

        return ret.toArray(new EnrollOrPollCertsResponse.Entry[0]);
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

    for (CertTemplateData certTemplate : certTemplates) {
      BigInteger certReqId = certTemplate.getCertReqId();

      byte[] certBytes = null;
      byte[] privateKeyBytes = null;
      ErrorEntry error = null;
      try {
        CertificateInfo certInfo = ca.generateCert(requestor, certTemplate, tid);

        if (explicitConfirm) {
          pendingCertPool.addCertificate(tid, certReqId, certInfo, waitForConfirmUtil);
        }

        if (certInfo.getPrivateKey() != null) {
          try {
            privateKeyBytes = certInfo.getPrivateKey().getEncoded();
          } catch (IOException e) {
            error = new ErrorEntry(SYSTEM_FAILURE, "error encoding CRL");
          }
        }

        if (error == null) {
          certBytes = certInfo.getCert().getCert().getEncoded();
        }
      } catch (OperationException ex) {
        error = new ErrorEntry(ex.getErrorCode(), ex.getErrorMessage());
      }

      ret.add(new EnrollOrPollCertsResponse.Entry(certReqId, error, certBytes, privateKeyBytes));
    }

    return ret.toArray(new EnrollOrPollCertsResponse.Entry[0]);
  } // method generateCertificates

  protected SdkResponse confirmCertificates(RequestorInfo requestor, X509Ca ca, byte[] request)
      throws DecodeException {
    ConfirmCertsRequest req = ConfirmCertsRequest.decode(request);
    String tid = req.getTransactionId();
    boolean successful = true;
    for (ConfirmCertsRequest.Entry m : req.getEntries()) {
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
