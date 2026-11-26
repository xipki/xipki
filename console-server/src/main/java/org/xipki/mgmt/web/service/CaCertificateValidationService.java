// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.CaEntry;
import org.xipki.mgmt.web.ca.CaDomain.CaMgmtException;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.ca.Crypto.*;
import org.xipki.mgmt.web.core.*;

/**
 * Validates CA certificate material without network fetches or secret material.
 *
 * @author palos
 */
public class CaCertificateValidationService {
  public enum ValidationPurpose {
    IMPORT,
    SUB_CA,
    ACTIVATE
  }

  public record CertificateValidationResult(
      boolean valid,
      String diagnostic,
      List<X509Cert> chain,
      String issuer,
      boolean selfSigned,
      int pathLength,
      String certificateFingerprint,
      String subjectKeyFingerprint,
      boolean notYetValid,
      boolean expired) {
    public static CertificateValidationResult invalid(String diagnostic, X509Cert leaf) {
      return new CertificateValidationResult(
          false,
          diagnostic,
          leaf == null ? List.of() : List.of(leaf),
          leaf == null || leaf.getIssuer() == null ? null : leaf.getIssuer().toString(),
          CaCertificateValidationService.selfSigned(leaf),
          leaf == null ? -1 : leaf.getBasicConstraints(),
          fingerprint(leaf),
          null,
          false,
          false);
    }
  }

  public CaCertificateValidationService() {}

  public CertificateValidationResult validate(
      X509Cert leaf,
      List<X509Cert> suppliedChain,
      Optional<X509Cert> expectedParent,
      Instant at,
      ValidationPurpose purpose) {
    if (leaf == null) {
      return CertificateValidationResult.invalid("Certificate is required", null);
    }
    Instant time = at == null ? Instant.now() : at;
    boolean future = time.isBefore(leaf.getNotBefore());
    boolean expired = time.isAfter(leaf.getNotAfter());
    if (expired || (future && purpose != ValidationPurpose.IMPORT)) {
      return result(
          false,
          future ? "Certificate validity starts in the future" : "Certificate validity has expired",
          leaf,
          List.of(),
          future,
          expired);
    }
    int pathLen = leaf.getBasicConstraints();
    if (pathLen < 0) {
      return result(false, "Certificate is not a CA certificate", leaf, List.of(), false, false);
    }
    if (purpose == ValidationPurpose.SUB_CA && leaf.isSelfSigned()) {
      return result(
          false,
          "SubCA certificate must be issued by a parent; path length is not applicable to a root",
          leaf,
          List.of(),
          false,
          false);
    }
    boolean[] usage = leaf.getKeyUsage();
    if (usage == null || usage.length <= 5 || !usage[5]) {
      return result(
          false, "CA certificate does not allow keyCertSign", leaf, List.of(), false, false);
    }

    List<X509Cert> candidates = suppliedChain == null ? List.of() : suppliedChain;
    if (new HashSet<>(candidates.stream().map(CaCertificateValidationService::fingerprint).toList())
            .size()
        != candidates.size()) {
      return result(
          false,
          "Certificate chain contains duplicate certificates",
          leaf,
          List.of(),
          future,
          expired);
    }
    if (candidates.size() > 32) {
      return result(
          false, "Certificate chain exceeds 32 issuers", leaf, List.of(), future, expired);
    }
    List<X509Cert> chain = new ArrayList<>();
    chain.add(leaf);
    Set<String> seen = new HashSet<>();
    seen.add(fingerprint(leaf));
    try {
      X509Cert current = leaf;
      while (!selfSigned(current)) {
        List<X509Cert> matches = new ArrayList<>();
        for (X509Cert candidate : candidates) {
          if (!current.getIssuer().equals(candidate.getSubject())) {
            continue;
          }
          try {
            current.verify(candidate.getPublicKey());
            matches.add(candidate);
          } catch (Exception ignored) {
            /* Candidate names alone do not establish an issuer. */
          }
        }
        if (matches.size() != 1) {
          return result(
              false, "Certificate chain is incomplete or ambiguous", leaf, chain, future, expired);
        }
        current = matches.get(0);
        if (!seen.add(fingerprint(current))) {
          return result(false, "Certificate chain contains a cycle", leaf, chain, future, expired);
        }
        chain.add(current);
      }
      if (chain.size() != candidates.size() + 1) {
        return result(
            false,
            "Certificate chain contains unrelated certificates",
            leaf,
            chain,
            future,
            expired);
      }
      if (expectedParent.isPresent()
          && (chain.size() < 2
              || !fingerprint(expectedParent.get()).equals(fingerprint(chain.get(1))))) {
        return result(
            false,
            "Certificate chain does not match the expected parent",
            leaf,
            chain,
            future,
            expired);
      }
      Instant validationTime = time;
      for (int i = 0; i < chain.size(); i++) {
        var cert = chain.get(i);
        boolean[] issuerUsage = cert.getKeyUsage();
        if (cert.getBasicConstraints() < 0
            || issuerUsage == null
            || issuerUsage.length <= 5
            || !issuerUsage[5]) {
          return result(
              false,
              "Certificate chain issuer requires CA and keyCertSign",
              leaf,
              chain,
              future,
              expired);
        }
        if (time.isAfter(cert.getNotAfter())) {
          return result(
              false, "Certificate chain issuer validity has expired", leaf, chain, future, true);
        }
        if (time.isBefore(cert.getNotBefore())) {
          future = true;
          if (purpose != ValidationPurpose.IMPORT) {
            return result(
                false,
                "Certificate chain issuer validity starts in the future",
                leaf,
                chain,
                true,
                false);
          }
          if (cert.getNotBefore().isAfter(validationTime)) {
            validationTime = cert.getNotBefore();
          }
        }
        long below =
            chain.subList(0, i).stream().filter(c -> !c.getIssuer().equals(c.getSubject())).count();
        if (below > cert.getBasicConstraints()) {
          return result(
              false, "Certificate chain exceeds CA path length", leaf, chain, future, false);
        }
      }
      var top = chain.get(chain.size() - 1).toJceCert();
      top.checkValidity(Date.from(validationTime));
      {
        // Include the self-signature-verified root in the validated path as well
        // as the anchor so its critical extensions and NameConstraints are checked.
        var path =
            CertificateFactory.getInstance("X.509")
                .generateCertPath(chain.stream().map(X509Cert::toJceCert).toList());
        var params = new PKIXParameters(Set.of(new TrustAnchor(top, null)));
        params.setRevocationEnabled(
            false); // No network queries; callers report revocation as unknown unless separately
        // confirmed.
        params.setDate(Date.from(validationTime));
        CertPathValidator.getInstance("PKIX").validate(path, params);
      }
    } catch (Exception ex) {
      return result(false, "Certificate chain validation failed", leaf, chain, future, expired);
    }
    return result(true, null, leaf, List.copyOf(chain), future, false);
  }

  private static CertificateValidationResult result(
      boolean valid,
      String diagnostic,
      X509Cert leaf,
      List<X509Cert> chain,
      boolean future,
      boolean expired) {
    return new CertificateValidationResult(
        valid,
        diagnostic,
        chain,
        leaf.getIssuer() == null ? null : leaf.getIssuer().toString(),
        selfSigned(leaf),
        leaf.getBasicConstraints(),
        fingerprint(leaf),
        keyFingerprint(leaf),
        future,
        expired);
  }

  public static String fingerprint(X509Cert cert) {
    return cert == null ? null : hex(digest(cert.getEncoded()));
  }

  public static boolean requireNotKnownRevoked(CaManager manager, List<X509Cert> chain)
      throws CaMgmtException {
    boolean allKnown = true;
    var local = new HashMap<String, CaEntry>();
    for (String name : manager.getCaNames()) {
      var ca = manager.getCa(name);
      if (ca != null && ca.getCert() != null) {
        local.put(fingerprint(ca.getCert()), ca);
      }
    }
    for (int i = 0; i < chain.size(); i++) {
      var certificate = chain.get(i);
      var managed = local.get(fingerprint(certificate));
      if (managed != null && managed.getBase().getRevocationInfo() != null) {
        throw new IllegalArgumentException("Certificate chain contains a known revoked CA");
      }
      if (i + 1 < chain.size()) {
        var issuer = local.get(fingerprint(chain.get(i + 1)));
        var record =
            issuer == null
                ? null
                : manager.getCert(issuer.getIdent().getName(), certificate.getSerialNumber());
        if (record != null && record.isRevoked()) {
          throw new IllegalArgumentException(
              "Certificate chain contains a known revoked certificate");
        }
        if (record == null) {
          allKnown = false;
        }
      } else if (!selfSigned(certificate) && certificate.getIssuer() != null) {
        boolean found = false;
        for (var issuer : local.values()) {
          if (!certificate.getIssuer().equals(issuer.getCert().getSubject())) {
            continue;
          }
          try {
            certificate.verify(issuer.getCert().getPublicKey());
          } catch (Exception ignored) {
            continue;
          }
          var record = manager.getCert(issuer.getIdent().getName(), certificate.getSerialNumber());
          if (record != null && record.isRevoked()) {
            throw new IllegalArgumentException(
                "Certificate chain contains a known revoked certificate");
          }
          found |= record != null;
        }
        allKnown &= found;
      }
    }
    return allKnown;
  }

  public static boolean selfSigned(X509Cert cert) {
    if (cert == null || cert.getSubject() == null || !cert.getSubject().equals(cert.getIssuer())) {
      return false;
    }
    try {
      cert.verify(cert.getPublicKey());
      return true;
    } catch (Exception ex) {
      return false;
    }
  }

  public static String keyFingerprint(X509Cert cert) {
    try {
      return hex(digest(cert.getPublicKey().getEncoded()));
    } catch (Exception ex) {
      return null;
    }
  }

  private static byte[] digest(byte[] value) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(value);
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
  }

  private static String hex(byte[] bytes) {
    return HexFormat.of().formatHex(bytes);
  }
}
