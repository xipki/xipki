// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.ApiResponse;
import org.xipki.mgmt.web.security.AccessControl;
import org.xipki.mgmt.web.service.CaManagementService;
import org.xipki.mgmt.web.service.ProfileCapabilities.CertLevel;
import org.xipki.mgmt.web.service.ProfileCapabilitiesService;

/**
 * @author palos
 */
public class CaOptionsController {
  private final CaManagementService service;
  private final AccessControl access;

  public CaOptionsController(CaManagementService service, AccessControl access) {
    this.service = service;
    this.access = access;
  }

  public ApiResponse<Map<String, Object>> options(String ca) throws CaMgmtException {
    boolean creator = access.has("CA_CREATE_ROOT") || access.has("CA_IMPORT");
    if (!creator) {
      if (ca == null) {
        throw new AccessDeniedException("CA required");
      }
      if (!access.allowed("CA_CONFIG_READ", ca, null)) {
        access.require("CA_CRYPTO_CONFIG_UPDATE", ca, null);
      }
    }
    var result = new LinkedHashMap<String, Object>();
    if (creator) {
      var profiles = new TreeSet<String>();
      var capabilities = new ProfileCapabilitiesService(service.getCaManager());
      for (String name : service.getCaManager().getCertprofileNames()) {
        if (capabilities.describe(name).level() == CertLevel.ROOT_CA) {
          profiles.add(name);
        }
      }
      result.put("profiles", profiles);
    }
    result.put("signerTypes", List.of("PKCS12", "PKCS11"));
    result.put("algorithms", List.of("RSA2048", "RSA3072", "RSA4096", "EC_P256", "EC_P384"));
    return ApiResponse.ok(result);
  }

  public ApiResponse<List<Map<String, String>>> associations(String name, String kind)
      throws CaMgmtException {
    if (!Set.of("profile", "publisher", "requestor").contains(kind)) {
      throw new IllegalArgumentException("Unknown association kind");
    }
    String prefix = "CA_" + kind.toUpperCase(Locale.ROOT);
    if (kind.equals("requestor") && access.allowed("CA_REQUESTOR_ACCESS_UPDATE", name, null)) {
      access.require("CA_REQUESTOR_ACCESS_UPDATE", name, null);
    } else {
      access.require(prefix + "_BIND", name, null);
    }
    Set<String> names =
        switch (kind) {
          case "profile" -> service.getCaManager().getCertprofileNames();
          case "publisher" -> service.getCaManager().getPublisherNames();
          default -> service.getCaManager().getRequestorNames();
        };
    return ApiResponse.ok(new TreeSet<>(names).stream().map(n -> Map.of("name", n)).toList());
  }

  public ApiResponse<Map<String, Object>> crypto(String name) throws CaMgmtException {
    access.require("CA_CRYPTO_CONFIG_UPDATE", name, null);
    return ApiResponse.ok(
        Map.of(
            "signers",
            new TreeSet<>(service.getCaManager().getSignerNames()),
            "keypairgens",
            new TreeSet<>(service.getCaManager().getKeypairGenNames())));
  }
}
