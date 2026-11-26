// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.time.DateTimeException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import javax.security.auth.x500.X500Principal;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.Crypto.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.service.CaCertificateValidationService.ValidationPurpose;
import org.xipki.mgmt.web.service.ProfileCapabilities.CertLevel;

/**
 * @author palos
 */
public class CaConfigurationService {
  private final CaManagementService service;
  private final CaConfigurationMapper mapper;
  private final CaKeyMaterialService materials;
  private final CaCertificateValidationService certificates = new CaCertificateValidationService();

  public CaConfigurationService(
      CaManagementService service, CaConfigurationMapper mapper, CaKeyMaterialService materials) {
    this.service = service;
    this.mapper = mapper;
    this.materials = materials;
  }

  public CaEntry required(String name) throws CaMgmtException {
    var entry = service.getCaManager().getCa(name);
    if (entry == null) {
      throw new ApiException(404, "CA not found");
    }
    return entry;
  }

  private void available(String name) throws CaMgmtException {
    if (service.getCaManager().getCaNames().stream().anyMatch(n -> n.equalsIgnoreCase(name))) {
      throw new ApiException(409, "CA name already exists");
    }
  }

  public CaDto root(CreateRootCaRequest r) throws CaMgmtException {
    try (var guard = ProfileOperationLock.issuance()) {
      return rootLocked(r);
    }
  }

  private CaDto rootLocked(CreateRootCaRequest r) throws CaMgmtException {
    requireInactiveCreation(r.config);
    String name = CaConfigurationMapper.name(r.name);
    if (r.subject == null || r.subject.isBlank() || r.subject.length() > 4096) {
      throw new IllegalArgumentException("Subject required");
    }
    new X500Principal(r.subject);
    String profile = CaConfigurationMapper.name(r.profile);
    if (new ProfileCapabilitiesService(service.getCaManager()).describe(profile).level()
        != CertLevel.ROOT_CA) {
      throw new IllegalArgumentException("A supported RootCA profile is required");
    }
    Instant before = instant(r.notBefore), after = instant(r.notAfter);
    dates(before, after);
    if (r.serialNumber != null
        && !r.serialNumber.matches("(?:[1-9][0-9]*|0[xX][0-9a-fA-F]+|RANDOM:[1-9][0-9]?)")) {
      throw new IllegalArgumentException("Invalid serial number");
    }
    available(name);
    // Validate all public configuration before expensive key generation or the first write.
    mapper.create("PKCS12", r.config, r.nextCrlNo);
    var key = materials.prepare(r.key, null, true);
    var entry =
        new CaEntry(
            mapper.create(key.type(), r.config, r.nextCrlNo), new NameId(null, name), key.conf());
    X509Cert cert =
        service
            .getCaManager()
            .generateRootCa(entry, profile, r.subject, r.serialNumber, before, after);
    entry.setCert(cert);
    return describe(entry);
  }

  public CaDto importCa(ImportCaRequest r) throws CaMgmtException {
    requireInactiveCreation(r.config);
    String name = CaConfigurationMapper.name(r.name);
    X509Cert cert = CaKeyMaterialService.certificate(r.certificate);
    CaKeyMaterialService.requireCa(cert);
    List<X509Cert> chain = CaKeyMaterialService.certificates(r.certificateChain);
    var validation =
        certificates.validate(
            cert, chain, Optional.empty(), Instant.now(), ValidationPurpose.IMPORT);
    if (!validation.valid()) {
      throw new IllegalArgumentException(validation.diagnostic());
    }
    if (!requireNotKnownRevoked(validation.chain())
        && !Boolean.TRUE.equals(r.acceptUnknownRevocation)) {
      throw new IllegalArgumentException(
          "Explicit acceptance of externally unverified revocation status is required");
    }
    chain = validation.chain().subList(1, validation.chain().size());
    available(name);
    mapper.create("PKCS12", r.config, r.nextCrlNo);
    var key = materials.prepare(r.key, cert, false);
    var entry =
        new CaEntry(
            mapper.create(key.type(), r.config, r.nextCrlNo), new NameId(null, name), key.conf());
    entry.setCert(cert);
    entry.setCertchain(chain);
    service.getCaManager().addCa(entry);
    return describe(entry);
  }

  public CaDto describe(CaEntry entry) {
    var dto = CaDto.fromEntry(entry);
    if (entry.getCert() == null) {
      return dto;
    }
    var result =
        certificates.validate(
            entry.getCert(),
            entry.getCertchain(),
            Optional.empty(),
            Instant.now(),
            ValidationPurpose.IMPORT);
    dto.setChainStatus(
        result.valid()
            ? (result.notYetValid() ? "not-yet-valid" : "verified")
            : result.diagnostic());
    dto.setChainCertificateFingerprints(
        result.chain().stream().map(CaCertificateValidationService::fingerprint).toList());
    try {
      dto.setRevocationCheck(
          CaCertificateValidationService.requireNotKnownRevoked(
                  service.getCaManager(), result.chain())
              ? "local-evidence"
              : "unknown");
    } catch (IllegalArgumentException revoked) {
      dto.setRevocationCheck("known-revoked");
    } catch (CaMgmtException unavailable) {
      dto.setRevocationCheck("unknown");
    }
    if (result.valid() && result.chain().size() > 1) {
      dto.setParentCertificateFingerprint(
          CaCertificateValidationService.fingerprint(result.chain().get(1)));
    }
    return dto;
  }

  private static void requireInactiveCreation(CaConfigurationRequest config) {
    if (config != null && config.status != null && !"inactive".equalsIgnoreCase(config.status)) {
      throw new IllegalArgumentException(
          "New CA must be registered inactive; activate it after configuring associations");
    }
  }

  public CaConfigurationRequest config(String name) throws CaMgmtException {
    return mapper.read(required(name));
  }

  public void update(String name, CaConfigurationRequest request) throws CaMgmtException {
    var change = mapper.change(name, request);
    CaEntry current = required(name);
    if ("active".equalsIgnoreCase(request.status)
        || request.encodedCert != null
        || request.encodedCertchain != null) {
      var cert =
          request.encodedCert == null
              ? current.getCert()
              : CaKeyMaterialService.certificate(request.encodedCert);
      var chain =
          request.encodedCertchain == null
              ? current.getCertchain()
              : CaKeyMaterialService.certificates(request.encodedCertchain);
      var check =
          certificates.validate(
              cert,
              chain,
              Optional.empty(),
              Instant.now(),
              "active".equalsIgnoreCase(request.status)
                      || current.getBase().getStatus() == CaStatus.active
                  ? ValidationPurpose.ACTIVATE
                  : ValidationPurpose.IMPORT);
      if (!check.valid() || current.getBase().getRevocationInfo() != null) {
        throw new IllegalArgumentException(
            "CA chain or revocation status does not permit activation/replacement");
      }
      if (!requireNotKnownRevoked(check.chain())
          && !Boolean.TRUE.equals(request.acceptUnknownRevocation)) {
        throw new IllegalArgumentException(
            "Explicit acceptance of externally unverified revocation status is required");
      }
    }
    if (request.key != null) {
      X509Cert cert =
          request.encodedCert == null
              ? current.getCert()
              : CaKeyMaterialService.certificate(request.encodedCert);
      var key = materials.prepare(request.key, cert, false);
      change.setSignerType(key.type());
      change.setSignerConf(key.conf());
    }
    service.getCaManager().changeCa(change);
  }

  /** Local engine evidence is authoritative; offline revocation status remains unknown. */
  public boolean requireNotKnownRevoked(List<X509Cert> chain) throws CaMgmtException {
    return CaCertificateValidationService.requireNotKnownRevoked(service.getCaManager(), chain);
  }

  public static Instant instant(String s) {
    if (s == null || s.isBlank()) {
      return null;
    }
    if (!s.endsWith("Z")) {
      throw new IllegalArgumentException("Use UTC ISO-8601 time");
    }
    try {
      return Instant.parse(s);
    } catch (DateTimeException ex) {
      throw new IllegalArgumentException("Invalid UTC ISO-8601 time");
    }
  }

  public static void dates(Instant before, Instant after) {
    if (before != null && after != null && !before.isBefore(after)) {
      throw new IllegalArgumentException("Invalid time range");
    }
  }
}
