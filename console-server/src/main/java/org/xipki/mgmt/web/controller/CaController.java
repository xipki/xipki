// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.ca.Crypto.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.security.AccessControl;
import org.xipki.mgmt.web.security.AccountService;
import org.xipki.mgmt.web.security.CaFieldPermissions;
import org.xipki.mgmt.web.security.RecentAuthentication;
import org.xipki.mgmt.web.service.CaCertificateValidationService;
import org.xipki.mgmt.web.service.CaCertificateValidationService.ValidationPurpose;
import org.xipki.mgmt.web.service.CaConfigurationMapper;
import org.xipki.mgmt.web.service.CaConfigurationService;
import org.xipki.mgmt.web.service.CaEnrollmentRepository;
import org.xipki.mgmt.web.service.CaKeyMaterialService;
import org.xipki.mgmt.web.service.CaManagementService;
import org.xipki.util.misc.PemEncoder;
import org.xipki.util.misc.PemEncoder.PemLabel;

/**
 * CA management controller.
 *
 * @author palos
 */
public class CaController {

  private final CaManagementService service;
  private final CaConfigurationService configuration;
  private final AccessControl access;
  private final AccountService accounts;
  private final CaEnrollmentRepository enrollments;

  public CaController(
      CaManagementService service,
      CaConfigurationService configuration,
      AccessControl access,
      AccountService accounts,
      CaEnrollmentRepository enrollments) {
    this.service = service;
    this.configuration = configuration;
    this.access = access;
    this.accounts = accounts;
    this.enrollments = enrollments;
  }

  public ApiResponse<List<CaDto>> listCas() throws CaMgmtException {
    CaManager mgr = service.getCaManager();
    Set<String> names = access.visibleCaNames();
    Set<String> successful = mgr.getSuccessfulCaNames();
    Set<String> failed = mgr.getFailedCaNames();
    List<CaDto> list = new ArrayList<>();
    for (String name : names) {
      CaEntry entry = mgr.getCa(name);
      if (entry != null) {
        CaDto dto = configuration.describe(entry);
        dto.setRuntimeState(
            failed.contains(name) ? "failed" : successful.contains(name) ? "started" : "inactive");
        dto.setAliases(new ArrayList<>(mgr.getAliasesForCa(name)));
        list.add(access.publicView(dto, access.identity(name)));
      }
    }
    return ApiResponse.ok(list);
  }

  public ApiResponse<CaDto> getCa(String name) throws CaMgmtException {
    var identity = access.require("CA_READ", name, null);
    name = identity.name();
    CaManager mgr = service.getCaManager();
    CaEntry entry = mgr.getCa(name);
    if (entry == null) {
      throw new ApiException(404, "CA not found");
    }
    CaDto dto = configuration.describe(entry);
    dto.setRuntimeState(
        mgr.getFailedCaNames().contains(name)
            ? "failed"
            : mgr.getSuccessfulCaNames().contains(name) ? "started" : "inactive");
    dto.setAliases(new ArrayList<>(mgr.getAliasesForCa(name)));

    Set<CaProfileEntry> profiles =
        access.allows("CA_PROFILE_READ", identity, null) ? mgr.getCertprofilesForCa(name) : null;
    if (profiles != null) {
      dto.setProfiles(
          profiles.stream().map(CaProfileEntry::getProfileName).collect(Collectors.toList()));
    }

    Set<String> publishers =
        access.allows("CA_PUBLISHER_READ", identity, null)
            ? mgr.getPublisherNamesForCa(name)
            : null;
    if (publishers != null) {
      dto.setPublishers(new ArrayList<>(publishers));
    }

    return ApiResponse.ok(access.publicView(dto, identity));
  }

  public ApiResponse<CaDto> addCa(ImportCaRequest request) throws CaMgmtException {
    access.requireGlobal("CA_IMPORT");
    return ApiResponse.ok(configuration.importCa(request));
  }

  public ApiResponse<Map<String, Object>> preflight(CaCertificateRequest request)
      throws CaMgmtException {
    access.requireGlobal("CA_IMPORT");
    var cert = CaKeyMaterialService.certificate(request.certificate);
    var check =
        new CaCertificateValidationService()
            .validate(
                cert,
                CaKeyMaterialService.certificates(request.certificateChain),
                Optional.empty(),
                Instant.now(),
                ValidationPurpose.IMPORT);
    var result = new LinkedHashMap<String, Object>();
    result.put("valid", check.valid());
    result.put("diagnostic", check.diagnostic());
    result.put("subject", cert.getSubject().toString());
    result.put("issuer", check.issuer());
    result.put("selfSigned", check.selfSigned());
    result.put("certificateFingerprint", check.certificateFingerprint());
    result.put("pathLength", check.pathLength());
    result.put(
        "chainFingerprints",
        check.chain().stream().map(CaCertificateValidationService::fingerprint).toList());
    result.put("notBefore", cert.getNotBefore().toString());
    result.put("notAfter", cert.getNotAfter().toString());
    if (check.valid()) {
      try {
        result.put(
            "revocationCheck",
            configuration.requireNotKnownRevoked(check.chain()) ? "local-evidence" : "unknown");
      } catch (IllegalArgumentException ex) {
        result.put("valid", false);
        result.put("diagnostic", "Certificate chain contains a known revoked certificate");
      }
    }
    return ApiResponse.ok(result);
  }

  public ApiResponse<CaDto> createRoot(CreateRootCaRequest request) throws CaMgmtException {
    access.requireGlobal("CA_CREATE_ROOT");
    return ApiResponse.ok(configuration.root(request));
  }

  public ApiResponse<CaConfigurationRequest> config(String name) throws CaMgmtException {
    name = access.require("CA_CONFIG_READ", name, null).name();
    return ApiResponse.ok(configuration.config(name));
  }

  public ApiResponse<Void> updateCa(String name, CaConfigurationRequest request)
      throws CaMgmtException {
    name = CaFieldPermissions.authorize(access, name, request);
    configuration.update(name, request);
    return ApiResponse.ok();
  }

  public Reply<byte[]> certificates(String name, String format) throws CaMgmtException {
    name = access.require("CA_READ", name, null).name();
    var entry = configuration.required(name);
    if (entry.getCert() == null) {
      throw new ApiException(404, "CA certificate not found");
    }
    if ("der".equals(format)) {
      return Reply.ok()
          .contentType("application/pkix-cert")
          .header("Content-Disposition", "attachment; filename=\"ca-certificate.der\"")
          .body(entry.getCert().getEncoded());
    }
    if (!"pem".equals(format)) {
      throw new IllegalArgumentException("Unsupported certificate format");
    }
    var certs = service.getCaManager().getCaCerts(name);
    if (certs == null || certs.isEmpty()) {
      certs = List.of(entry.getCert());
    }
    var output = new ByteArrayOutputStream();
    for (var cert : certs) {
      output.writeBytes(PemEncoder.encode(cert.getEncoded(), PemLabel.CERTIFICATE));
    }
    return Reply.ok()
        .contentType("application/x-pem-file")
        .header("Content-Disposition", "attachment; filename=\"ca-certificates.pem\"")
        .body(output.toByteArray());
  }

  public ApiResponse<Void> removeCa(String name, String confirmName) throws CaMgmtException {
    var identity = access.require("CA_DELETE", name, null);
    name = identity.name();
    RecentAuthentication.require();
    if (!name.equals(confirmName)) {
      throw new IllegalArgumentException("CA name confirmation required");
    }
    String caName = name;
    CaRemoval.remove(
        service.getCaManager(),
        caName,
        () -> accounts.revokeCaBindings(caName, identity.fingerprint()));
    return ApiResponse.ok();
  }

  public ApiResponse<Void> revokeCa(String name, Map<String, String> request)
      throws CaMgmtException {
    name = access.require("CA_REVOKE", name, null).name();
    String reasonStr = request.getOrDefault("reason", "unspecified");
    CrlReason reason = CrlReason.forNameOrText(reasonStr);
    if (reason == CrlReason.REMOVE_FROM_CRL) {
      throw new IllegalArgumentException("Use unrevoke instead");
    }
    Instant invalidity = CaConfigurationService.instant(request.get("invalidityTime"));
    if (invalidity != null && invalidity.isAfter(Instant.now())) {
      throw new IllegalArgumentException("Invalidity time cannot be in the future");
    }
    CertRevocationInfo revInfo = new CertRevocationInfo(reason, Instant.now(), invalidity);
    service.getCaManager().revokeCa(name, revInfo);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> unrevokeCa(String name) throws CaMgmtException {
    name = access.require("CA_UNREVOKE", name, null).name();
    service.getCaManager().unrevokeCa(name);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> restartCa(String name) throws CaMgmtException {
    name = access.require("CA_RESTART", name, null).name();
    service.getCaManager().restartCa(name);
    return ApiResponse.ok();
  }

  // --- Alias management ---

  public ApiResponse<Map<String, String>> listAliases() throws CaMgmtException {
    CaManager mgr = service.getCaManager();
    Set<String> aliases = mgr.getCaAliasNames();
    Map<String, String> result = new LinkedHashMap<>();
    for (String alias : aliases) {
      String name = mgr.getCaNameForAlias(alias);
      if (access.allowed("CA_READ", name, null)) {
        result.put(alias, name);
      }
    }
    return ApiResponse.ok(result);
  }

  public ApiResponse<Void> addAlias(Map<String, String> request) throws CaMgmtException {
    String name = access.require("CA_ALIAS_CREATE", request.get("caName"), null).name();
    service.getCaManager().addCaAlias(CaConfigurationMapper.name(request.get("alias")), name);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> removeAlias(String alias) throws CaMgmtException {
    access.require("CA_ALIAS_DELETE", service.getCaManager().getCaNameForAlias(alias), null);
    service.getCaManager().removeCaAlias(alias);
    return ApiResponse.ok();
  }

  public ApiResponse<Map<String, Object>> deleteImpact(String name) throws CaMgmtException {
    var identity = access.require("CA_DELETE", name, null);
    name = identity.name();
    var manager = service.getCaManager();
    var children = new ArrayList<String>();
    var references = new ArrayList<String>();
    for (String visible : access.visibleCaNames()) {
      if (visible.equals(name)) {
        continue;
      }
      var entry = manager.getCa(visible);
      if (entry == null) {
        continue;
      }
      var related = configuration.describe(entry);
      if (identity.fingerprint().equals(related.getParentCertificateFingerprint())) {
        children.add(visible);
      }
      if (related.getChainCertificateFingerprints() != null
          && related.getChainCertificateFingerprints().contains(identity.fingerprint())) {
        references.add(visible);
      }
    }
    return ApiResponse.ok(
        Map.of(
            "name",
            name,
            "namedGrantCount",
            accounts.caBindingCount(name, identity.fingerprint()),
            "profiles",
            manager.getCertprofilesForCa(name).stream()
                .map(CaProfileEntry::getProfileName)
                .toList(),
            "publishers",
            manager.getPublisherNamesForCa(name),
            "aliases",
            manager.getAliasesForCa(name),
            "visibleChildCas",
            children,
            "visibleChainReferences",
            references,
            "pendingEnrollmentCount",
            enrollments.pendingForParent(identity.fingerprint())));
  }
}
