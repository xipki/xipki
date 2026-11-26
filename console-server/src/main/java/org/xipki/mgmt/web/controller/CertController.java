// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.security.auth.x500.X500Principal;
import org.xipki.mgmt.web.audit.AuditTargetCapture;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.Crypto.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.ApiResponse;
import org.xipki.mgmt.web.dto.CertDto;
import org.xipki.mgmt.web.dto.KeyCertDownloadRequest;
import org.xipki.mgmt.web.security.AccessControl;
import org.xipki.mgmt.web.security.CertificateOwnership;
import org.xipki.mgmt.web.service.CaManagementService;
import org.xipki.mgmt.web.service.CertificateMaterial;
import org.xipki.mgmt.web.service.ProfileOperationLock;
import org.xipki.util.misc.PemEncoder;
import org.xipki.util.misc.PemEncoder.PemLabel;

/**
 * Certificate management controller.
 *
 * @author palos
 */
public class CertController {

  private final CaManagementService service;
  private final AccessControl access;
  private final CertificateOwnership ownership;

  public CertController(
      CaManagementService service, AccessControl access, CertificateOwnership ownership) {
    this.service = service;
    this.access = access;
    this.ownership = ownership;
  }

  public ApiResponse<List<CertDto>> listCerts(
      HttpServletResponse response,
      String ca,
      String subject,
      String validFrom,
      String validTo,
      String orderBy,
      int limit,
      boolean paged,
      String cursor)
      throws CaMgmtException {

    CertificateMaterial.required(ca);
    if (limit < 1 || limit > 1000) {
      throw new IllegalArgumentException("Invalid query limit");
    }
    X500Principal subjectPattern =
        (subject != null && !subject.isEmpty()) ? new X500Principal(subject) : null;
    String subjectGlob = subjectPattern == null ? null : subjectGlob(subjectPattern);
    if (subjectGlob != null && subjectGlob.indexOf('%') >= 0) {
      throw new IllegalArgumentException("Invalid subject pattern");
    }
    Instant from = CertificateMaterial.time(validFrom);
    Instant to = CertificateMaterial.time(validTo);
    CertificateMaterial.range(from, to);
    CertListOrderBy order = CertListOrderBy.forValue(orderBy);
    if (order == null) {
      throw new IllegalArgumentException("Invalid query order");
    }
    var identity = access.require("CERT_READ", ca, null);
    ca = identity.name();
    service.requireStarted(ca);
    if (!access.allows("CERT_READ_ALL", identity, null)) {
      if (!paged && cursor != null) {
        throw new IllegalArgumentException("Cursor requires paged search");
      }
      List<String> serials;
      if (paged) {
        var page = ownership.page(identity, cursor);
        if (page.nextCursor() != null) {
          response.setHeader("X-Next-Cursor", page.nextCursor());
        }
        serials = page.serials();
      } else {
        serials = ownership.serials(identity, 1001);
        if (serials.size() > 1000) {
          throw new ApiException(
              409, "Certificate history exceeds the legacy query limit; use paged=true");
        }
      }
      var own = new ArrayList<CertDto>();
      for (String serial : serials) {
        var info = service.getCaManager().getCert(ca, CertificateMaterial.serial(serial));
        if (info == null) {
          continue;
        }
        var cert = info.getCert().getCert();
        if (subjectGlob != null && !matchesSubject(subjectGlob, cert.getSubjectText())) {
          continue;
        }
        // Match XiPKI's listCertificates predicates, including its second-level bounds.
        if (from != null && cert.getNotBefore().getEpochSecond() >= from.getEpochSecond() - 1) {
          continue;
        }
        if (to != null && cert.getNotAfter().getEpochSecond() <= to.getEpochSecond()) {
          continue;
        }
        own.add(CertDto.fromCertWithRevocation(info));
      }
      Comparator<CertDto> comparator =
          orderBy.startsWith("subject")
              ? Comparator.comparing(CertDto::getSubject)
              : orderBy.startsWith("notAfter")
                  ? Comparator.comparing(CertDto::getNotAfter)
                  : Comparator.comparing(CertDto::getNotBefore);
      own.sort(orderBy.endsWith("-desc") ? comparator.reversed() : comparator);
      return ApiResponse.ok(own.stream().limit(limit).toList());
    }
    if (cursor != null) {
      throw new IllegalArgumentException("Cursor is only valid for personal certificates");
    }

    List<CertListInfo> certs =
        service.getCaManager().listCertificates(ca, subjectPattern, from, to, order, limit);
    List<CertDto> result =
        certs.stream().map(CertDto::fromCertListInfo).collect(Collectors.toList());
    return ApiResponse.ok(result);
  }

  private static String subjectGlob(X500Principal principal) {
    try {
      var rdns = new ArrayList<>(new LdapName(principal.getName(X500Principal.RFC2253)).getRdns());
      Collections.reverse(rdns);
      return rdns.stream()
          .map(Object::toString)
          .collect(Collectors.joining("*"))
          .toLowerCase(Locale.ROOT);
    } catch (InvalidNameException ex) {
      throw new IllegalArgumentException("Invalid subject pattern", ex);
    }
  }

  private static boolean matchesSubject(String glob, String subject) {
    String pattern = "*" + glob + "*";
    String value = subject.toLowerCase(Locale.ROOT);
    int p = 0, s = 0, star = -1, retry = 0;
    while (s < value.length()) {
      if (p < pattern.length()
          && (pattern.charAt(p) == '_' || pattern.charAt(p) == value.charAt(s))) {
        p++;
        s++;
      } else if (p < pattern.length() && pattern.charAt(p) == '*') {
        star = p++;
        retry = s;
      } else if (star >= 0) {
        p = star + 1;
        s = ++retry;
      } else {
        return false;
      }
    }
    while (p < pattern.length() && pattern.charAt(p) == '*') {
      p++;
    }
    return p == pattern.length();
  }

  public ApiResponse<CertDto> getCert(String ca, String serial) throws CaMgmtException {
    BigInteger serialNumber = CertificateMaterial.serial(serial);
    ca = requireRead(ca, serialNumber);
    CertWithRevocationInfo info = service.getCaManager().getCert(ca, serialNumber);
    if (info == null) {
      throw new ApiException(404, "Resource not found");
    }
    return ApiResponse.ok(CertDto.fromCertWithRevocation(info));
  }

  public ApiResponse<CertDto> enrollCert(
      HttpServletRequest request,
      String ca,
      String profile,
      Upload csrFile,
      String notBefore,
      String notAfter)
      throws Exception {

    CertificateMaterial.checkRequestSize(request.getContentLengthLong());
    try (var guard = ProfileOperationLock.issuance()) {
      CertificateMaterial.required(ca);
      CertificateMaterial.required(profile);
      byte[] csrBytes = CertificateMaterial.csr(csrFile);
      Instant nb = CertificateMaterial.time(notBefore);
      Instant na = CertificateMaterial.time(notAfter);
      CertificateMaterial.range(nb, na);
      var grant = access.requireIssue("CERT_ISSUE", ca, profile);
      ca = grant.ca().name();
      profile = grant.profile();
      X509Cert cert = service.getCaManager().generateCertificate(ca, profile, csrBytes, nb, na);
      AuditTargetCapture.identify(request, "serial", cert.getSerialNumber().toString(16));
      ownership.record(grant.ca(), cert.getSerialNumber().toString(16), profile);

      return ApiResponse.ok(publicCertificate(cert));
    }
  }

  public ApiResponse<CertDto> enrollCross(
      HttpServletRequest request,
      String ca,
      String profile,
      Upload csr,
      Upload targetCert,
      String notBefore,
      String notAfter)
      throws Exception {
    try (var guard = ProfileOperationLock.issuance()) {
      CertificateMaterial.checkRequestSize(request.getContentLengthLong());
      CertificateMaterial.required(ca);
      CertificateMaterial.required(profile);
      byte[] csrDer = CertificateMaterial.csr(csr);
      byte[] targetDer = CertificateMaterial.certificate(targetCert, csrDer);
      Instant nb = CertificateMaterial.time(notBefore);
      Instant na = CertificateMaterial.time(notAfter);
      CertificateMaterial.range(nb, na);
      var grant = access.requireIssue("CERT_CROSS", ca, profile);
      ca = grant.ca().name();
      profile = grant.profile();
      X509Cert cert =
          service.getCaManager().generateCrossCertificate(ca, profile, csrDer, targetDer, nb, na);
      AuditTargetCapture.identify(request, "serial", cert.getSerialNumber().toString(16));
      ownership.record(grant.ca(), cert.getSerialNumber().toString(16), profile);
      return ApiResponse.ok(publicCertificate(cert));
    }
  }

  private CertDto publicCertificate(X509Cert cert) throws Exception {
    CertDto dto = new CertDto();
    dto.setSubject(cert.getSubjectText());
    dto.setIssuer(cert.getIssuerText());
    dto.setSerialNumber(cert.getSerialNumber().toString(16));
    dto.setNotBefore(cert.getNotBefore().toString());
    dto.setNotAfter(cert.getNotAfter().toString());
    dto.setCertPem(
        new String(
            PemEncoder.encode(cert.getEncoded(), PemLabel.CERTIFICATE),
            StandardCharsets.UTF_8));
    return dto;
  }

  public Reply<byte[]> downloadKeyCert(HttpServletRequest request, KeyCertDownloadRequest body)
      throws Exception {
    try (var guard = ProfileOperationLock.issuance()) {
      CertificateMaterial.checkRequestSize(request.getContentLengthLong());
      CertificateMaterial.required(body.getCa());
      CertificateMaterial.required(body.getProfile());
      new X500Principal(CertificateMaterial.required(body.getSubject()));
      if (body.getDownloadPassword() == null || body.getDownloadPassword().length() < 12) {
        throw new IllegalArgumentException("Download password must contain at least 12 characters");
      }
      Instant nb = CertificateMaterial.time(body.getNotBefore());
      Instant na = CertificateMaterial.time(body.getNotAfter());
      CertificateMaterial.range(nb, na);
      var grant = access.requireIssue("CERT_KEYGEN", body.getCa(), body.getProfile());
      var manager = service.getCaManager();
      CertificateMaterial.requireKeypairGenerator(manager, grant.ca().name());
      var chain = manager.getCaCerts(grant.ca().name());
      var pair =
          manager.generateKeyCert(grant.ca().name(), grant.profile(), body.getSubject(), nb, na);
      AuditTargetCapture.identify(
          request, "serial", X509Util.parseCert(pair.getCert()).getSerialNumber().toString(16));
      ownership.record(
          grant.ca(),
          X509Util.parseCert(pair.getCert()).getSerialNumber().toString(16),
          grant.profile());
      char[] password = body.getDownloadPassword().toCharArray();
      body.setDownloadPassword(null);
      byte[] pkcs12 = CertificateMaterial.pkcs12(pair, chain, password);
      return Reply.ok()
          .contentType("application/x-pkcs12")
          .header("Cache-Control", "no-store")
          .header(
              "X-Certificate-Serial",
              X509Util.parseCert(pair.getCert()).getSerialNumber().toString(16))
          .header("Content-Disposition", "attachment; filename=\"key-certificate.p12\"")
          .body(pkcs12);
    }
  }

  public ApiResponse<Map<String, String>> enrollKeyCert(
      HttpServletRequest request,
      HttpServletResponse response,
      String ca,
      String profile,
      String subject,
      String notBefore,
      String notAfter)
      throws Exception {

    try (var guard = ProfileOperationLock.issuance()) {
      response.setHeader("Cache-Control", "no-store");
      CertificateMaterial.required(ca);
      CertificateMaterial.required(profile);
      new X500Principal(CertificateMaterial.required(subject));
      Instant nb = CertificateMaterial.time(notBefore);
      Instant na = CertificateMaterial.time(notAfter);
      CertificateMaterial.range(nb, na);
      var grant = access.requireIssue("CERT_KEYGEN", ca, profile);
      ca = grant.ca().name();
      profile = grant.profile();
      CertificateMaterial.requireKeypairGenerator(service.getCaManager(), ca);
      KeyCertBytesPair pair = service.getCaManager().generateKeyCert(ca, profile, subject, nb, na);
      AuditTargetCapture.identify(
          request, "serial", X509Util.parseCert(pair.getCert()).getSerialNumber().toString(16));
      ownership.record(
          grant.ca(), X509Util.parseCert(pair.getCert()).getSerialNumber().toString(16), profile);

      Map<String, String> result = new LinkedHashMap<>();
      result.put("cert", Base64.getEncoder().encodeToString(pair.getCert()));
      result.put("key", Base64.getEncoder().encodeToString(pair.getKey()));
      return ApiResponse.ok(result);
    }
  }

  public ApiResponse<Void> revokeCert(String ca, String serial, Map<String, String> request)
      throws CaMgmtException {
    BigInteger serialNumber = CertificateMaterial.serial(serial);
    if (!Set.of("reason", "invalidityTime").containsAll(request.keySet())) {
      throw new IllegalArgumentException("Unsupported revoke field");
    }
    String reasonStr = request.getOrDefault("reason", "unspecified");
    CrlReason reason = CrlReason.forNameOrText(reasonStr);
    ca =
        access
            .require(
                reason == CrlReason.CERTIFICATE_HOLD ? "CERT_SUSPEND" : "CERT_REVOKE", ca, null)
            .name();
    service.requireStarted(ca);
    if (reason == CrlReason.REMOVE_FROM_CRL) {
      throw new IllegalArgumentException("Use unsuspend for held certificates");
    }
    String invTimeStr = request.get("invalidityTime");
    Instant invalidityTime = CertificateMaterial.time(invTimeStr);
    if (invalidityTime != null && invalidityTime.isAfter(Instant.now())) {
      throw new IllegalArgumentException("Future invalidity time");
    }

    service.getCaManager().revokeCertificate(ca, serialNumber, reason, invalidityTime);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> unsuspendCert(String ca, String serial) throws CaMgmtException {
    ca = access.require("CERT_UNSUSPEND", ca, null).name();
    service.requireStarted(ca);
    BigInteger serialNumber = CertificateMaterial.serial(serial);
    service.getCaManager().unsuspendCertificate(ca, serialNumber);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> removeCert(String ca, String serial) throws CaMgmtException {
    ca = access.require("CERT_DELETE", ca, null).name();
    service.requireStarted(ca);
    BigInteger serialNumber = CertificateMaterial.serial(serial);
    service.getCaManager().removeCertificate(ca, serialNumber);
    return ApiResponse.ok();
  }

  public Reply<byte[]> downloadCert(String ca, String serial, String format) throws Exception {
    BigInteger serialNumber = CertificateMaterial.serial(serial);
    if (!Set.of("pem", "der").contains(format.toLowerCase(Locale.ROOT))) {
      throw new IllegalArgumentException("Invalid certificate format");
    }
    ca = requireRead(ca, serialNumber);
    CertWithRevocationInfo info = service.getCaManager().getCert(ca, serialNumber);
    if (info == null) {
      return Reply.status(404).build();
    }

    byte[] encoded = info.getCert().getCert().getEncoded();
    String filename = "cert-" + serial;
    String mediaType;

    if ("pem".equalsIgnoreCase(format)) {
      encoded = PemEncoder.encode(encoded, PemLabel.CERTIFICATE);
      filename += ".pem";
      mediaType = "text/plain";
    } else {
      filename += ".der";
      mediaType = "application/octet-stream";
    }

    return Reply.ok()
        .contentType(mediaType)
        .header("Content-Disposition", "attachment; filename=\"" + filename + "\"")
        .body(encoded);
  }

  private String requireRead(String ca, BigInteger serial) throws CaMgmtException {
    var identity = access.require("CERT_READ", ca, null);
    if (!access.allows("CERT_READ_ALL", identity, null)
        && !ownership.owns(identity, serial.toString(16))) {
      throw new AccessDeniedException("Permission denied");
    }
    service.requireStarted(identity.name());
    return identity.name();
  }
}
