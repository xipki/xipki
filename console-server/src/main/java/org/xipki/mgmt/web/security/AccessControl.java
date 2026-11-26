// License Apache License 2.0

package org.xipki.mgmt.web.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.Crypto.X509Cert;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.CaDto;
import org.xipki.mgmt.web.service.CaCertificateValidationService;
import org.xipki.mgmt.web.service.CaManagementService;
import org.xipki.mgmt.web.service.ProfileCapabilities.CertLevel;
import org.xipki.mgmt.web.service.ProfileCapabilitiesService;

/**
 * One authorization boundary shared by all CA/certificate entry points.
 *
 * @author palos
 */
public class AccessControl {
  private final CaManagementService service;

  public AccessControl(CaManagementService service) {
    this.service = service;
  }

  public record CaIdentity(String name, String fingerprint) {}

  public record Issuance(CaIdentity ca, String profile) {}

  public boolean has(String permission) {
    return AccountService.principal().getAuthorities().stream()
        .anyMatch(a -> ("PERM_" + permission).equals(a.getAuthority()));
  }

  public void requireGlobal(String permission) {
    var principal = AccountService.principal();
    if (!PermissionCatalog.get(permission).scope().equals("PLATFORM")
        || !has(permission)
        || !principal.isSuperAdmin()
            && principal.bindings().stream()
                .noneMatch(
                    b ->
                        b.scope().equals("PLATFORM")
                            && b.definition().active()
                            && b.definition().permissions().contains(permission))) {
      throw denied();
    }
    if (PermissionCatalog.get(permission).recentAuthRequired()) {
      RecentAuthentication.require();
    }
  }

  public CaIdentity identity(String input) throws CaMgmtException {
    if (input == null || !input.matches("[a-zA-Z0-9_.-]{1,128}")) {
      throw denied();
    }
    String name = input.toLowerCase(Locale.ROOT);
    var manager = service.getCaManager();
    // The remote API throws on missing names rather than returning null.
    // Resolve from public name sets first so missing and ungranted targets
    // have the same denial response. Transport errors still propagate.
    if (!manager.getCaNames().contains(name)) {
      if (!manager.getCaAliasNames().contains(name)) {
        throw denied();
      }
      name = manager.getCaNameForAlias(name);
      if (name == null) {
        throw denied();
      }
    }
    var entry = manager.getCa(name);
    if (entry == null || entry.getCert() == null) {
      throw denied();
    }
    return new CaIdentity(entry.getIdent().getName(), fingerprint(entry.getCert().getEncoded()));
  }

  public boolean allowed(String permission, String ca, String profile) throws CaMgmtException {
    if (!has(permission)) {
      return false;
    }
    try {
      return allows(permission, identity(ca), profile);
    } catch (AccessDeniedException ex) {
      return false;
    }
  }

  public boolean allows(String permission, CaIdentity identity, String profile) {
    return AccountService.principal().bindings().stream()
        .anyMatch(b -> b.allows(permission, identity.name(), identity.fingerprint(), profile));
  }

  public CaIdentity require(String permission, String ca, String profile) throws CaMgmtException {
    if (!has(permission)) {
      throw denied();
    }
    var identity = identity(ca);
    if (!allows(permission, identity, profile)) {
      throw denied();
    }
    return identity;
  }

  public Issuance requireIssue(String permission, String ca, String requestedProfile)
      throws CaMgmtException {
    if (!has(permission)) {
      throw denied();
    }
    var identity = identity(ca);
    String canonical = null;
    var entries = service.getCaManager().getCertprofilesForCa(identity.name());
    if (entries != null && requestedProfile != null) {
      for (var entry : entries) {
        if (entry.getProfileName().equalsIgnoreCase(requestedProfile)
            || entry.getProfileAliases().stream()
                .anyMatch(a -> a.equalsIgnoreCase(requestedProfile))) {
          canonical = entry.getProfileName();
          break;
        }
      }
    }
    if (canonical == null || !allows(permission, identity, canonical)) {
      throw denied();
    }
    var level = new ProfileCapabilitiesService(service.getCaManager()).describe(canonical).level();
    if (level == CertLevel.UNKNOWN || level == CertLevel.ROOT_CA) {
      throw denied();
    }
    if (permission.equals("CERT_CROSS") && level != CertLevel.CROSS) {
      throw denied();
    }
    if (level == CertLevel.SUB_CA) {
      if (!has("CA_ISSUE_SUBCA") || !allows("CA_ISSUE_SUBCA", identity, canonical)) {
        throw denied();
      }
      RecentAuthentication.require();
    } else if (permission.equals("CA_ISSUE_SUBCA")) {
      throw denied();
    }
    if (level == CertLevel.CROSS && !permission.equals("CERT_CROSS")) {
      throw denied();
    }
    var caEntry = service.getCaManager().getCa(identity.name());
    if (caEntry.getBase() == null
        || caEntry.getBase().getStatus() != CaStatus.active
        || !service.getCaManager().getSuccessfulCaNames().contains(identity.name())
        || caEntry.getBase().getRevocationInfo() != null) {
      throw denied();
    }
    var chain = new ArrayList<X509Cert>();
    chain.add(caEntry.getCert());
    if (caEntry.getCertchain() != null) {
      chain.addAll(caEntry.getCertchain());
    }
    CaCertificateValidationService.requireNotKnownRevoked(service.getCaManager(), chain);
    return new Issuance(identity, canonical);
  }

  public Issuance requireSubCaIssue(String ca, String profile) throws CaMgmtException {
    return requireIssue("CA_ISSUE_SUBCA", ca, profile);
  }

  public Set<String> visibleCaNames() throws CaMgmtException {
    var result = new TreeSet<String>();
    if (!has("CA_READ")) {
      return result;
    }
    for (String name : service.getCaManager().getCaNames()) {
      if (allowed("CA_READ", name, null)) {
        result.add(name);
      }
    }
    return result;
  }

  public List<String> allowedProfiles(String ca) throws CaMgmtException {
    var identity = require("CA_READ", ca, null);
    var result = new TreeSet<String>();
    var entries = service.getCaManager().getCertprofilesForCa(identity.name());
    if (entries != null) {
      for (var entry : entries) {
        if (allows("CA_PROFILE_READ", identity, null)
            || allows("CERT_ISSUE", identity, entry.getProfileName())
            || allows("CERT_KEYGEN", identity, entry.getProfileName())
            || allows("CERT_CROSS", identity, entry.getProfileName())
            || allows("CA_ISSUE_SUBCA", identity, entry.getProfileName())) {
          result.add(entry.getProfileName());
        }
      }
    }
    return List.copyOf(result);
  }

  public List<String> issuanceProfiles(String ca, String permission) throws CaMgmtException {
    if (!PermissionCatalog.ISSUANCE.contains(permission) || !has(permission)) {
      throw denied();
    }
    var identity = require("CA_READ", ca, null);
    var result = new TreeSet<String>();
    for (var binding : service.getCaManager().getCertprofilesForCa(identity.name())) {
      String profile = binding.getProfileName();
      if (!allows(permission, identity, profile)) {
        continue;
      }
      var level = new ProfileCapabilitiesService(service.getCaManager()).describe(profile).level();
      if (level == CertLevel.UNKNOWN || level == CertLevel.ROOT_CA) {
        continue;
      }
      if (permission.equals("CERT_CROSS") != (level == CertLevel.CROSS)) {
        continue;
      }
      if (level == CertLevel.SUB_CA && !allows("CA_ISSUE_SUBCA", identity, profile)) {
        continue;
      }
      if (permission.equals("CA_ISSUE_SUBCA") && level != CertLevel.SUB_CA) {
        continue;
      }
      result.add(profile);
    }
    return List.copyOf(result);
  }

  public CaDto publicView(CaDto dto, CaIdentity identity) {
    if (!allows("CA_DETAIL_READ", identity, null)) {
      var minimal = new CaDto();
      minimal.setName(dto.getName());
      minimal.setStatus(dto.getStatus());
      minimal.setSubject(dto.getSubject());
      minimal.setSerialNumber(dto.getSerialNumber());
      minimal.setNotBefore(dto.getNotBefore());
      minimal.setNotAfter(dto.getNotAfter());
      minimal.setCertPem(dto.getCertPem());
      minimal.setRuntimeState(dto.getRuntimeState());
      minimal.setAliases(dto.getAliases());
      minimal.setRevocationInfo(dto.getRevocationInfo());
      minimal.setIssuer(dto.getIssuer());
      minimal.setCertificateFingerprint(dto.getCertificateFingerprint());
      minimal.setSelfSigned(dto.isSelfSigned());
      minimal.setRevocationCheck(dto.getRevocationCheck());
      minimal.setSubjectKeyFingerprint(dto.getSubjectKeyFingerprint());
      minimal.setPathLength(dto.getPathLength());
      minimal.setChainStatus(dto.getChainStatus());
      minimal.setChainCertificateFingerprints(dto.getChainCertificateFingerprints());
      minimal.setParentCertificateFingerprint(dto.getParentCertificateFingerprint());
      dto = minimal;
    }
    dto.setCertificateFingerprint(identity.fingerprint());
    var permissions = new TreeSet<String>();
    for (var binding : AccountService.principal().bindings()) {
      for (String permission : binding.definition().permissions()) {
        if (binding.allows(permission, identity.name(), identity.fingerprint(), null)) {
          permissions.add(permission);
        }
      }
    }
    dto.setWebPermissions(List.copyOf(permissions));
    return dto;
  }

  public static String fingerprint(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException(ex);
    }
  }

  private static AccessDeniedException denied() {
    return new AccessDeniedException("Permission denied");
  }
}
