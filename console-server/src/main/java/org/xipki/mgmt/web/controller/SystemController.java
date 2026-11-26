// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.ApiResponse;
import org.xipki.mgmt.web.dto.RepublishRequest;
import org.xipki.mgmt.web.security.AccessControl;
import org.xipki.mgmt.web.security.RecentAuthentication;
import org.xipki.mgmt.web.service.CaManagementService;
import org.xipki.mgmt.web.service.CertificateMaterial;
import org.xipki.mgmt.web.service.ProfileOperationLock;

/**
 * @author palos
 */
public class SystemController {

  private final CaManagementService service;
  private final AccessControl access;

  public SystemController(CaManagementService service, AccessControl access) {
    this.service = service;
    this.access = access;
  }

  public ApiResponse<String> getSystemStatus() throws CaMgmtException {
    return ApiResponse.ok(service.getCaManager().getCaSystemStatus().name());
  }

  public ApiResponse<Void> restartSystem() throws CaMgmtException {
    service.getCaManager().restartCaSystem();
    return ApiResponse.ok();
  }

  public ApiResponse<Void> unlockSystem() throws CaMgmtException {
    service.getCaManager().unlockCa();
    return ApiResponse.ok();
  }

  public ApiResponse<Void> notifyChange() throws CaMgmtException {
    service.getCaManager().notifyCaChange();
    return ApiResponse.ok();
  }

  public ApiResponse<Void> republish(RepublishRequest request) throws CaMgmtException {
    String caName = request.getCaName();
    CertificateMaterial.required(caName);
    caName = access.require("CERT_REPUBLISH", caName, null).name();
    service.requireStarted(caName);
    List<String> publisherNames = request.getPublisherNames();
    if (request.getNumThreads() == null) {
      throw new IllegalArgumentException("Invalid thread count");
    }
    int numThreads = request.getNumThreads();
    if (numThreads < 1 || numThreads > 32) {
      throw new IllegalArgumentException("Invalid thread count");
    }
    if (publisherNames != null) {
      var associated = service.getCaManager().getPublisherNamesForCa(caName);
      for (String name : publisherNames) {
        CertificateMaterial.required(name);
        if (associated == null || !associated.contains(name)) {
          throw new IllegalArgumentException("Publisher is not associated with this CA");
        }
      }
    }

    service.getCaManager().republishCertificates(caName, publisherNames, numThreads);
    return ApiResponse.ok();
  }

  public Reply<byte[]> exportConf(List<String> caNames) throws Exception {
    RecentAuthentication.require();
    access.requireGlobal("CONFIG_EXPORT");
    if (caNames != null) {
      for (String name : caNames) {
        access.identity(name);
      }
    }
    byte[] data;
    try (InputStream stream = service.getCaManager().exportConf(caNames)) {
      data = stream.readAllBytes();
    }

    return Reply.ok()
        .header("Cache-Control", "no-store")
        .contentType("application/octet-stream")
        .header("Content-Disposition", "attachment; filename=\"xipki-conf-export.zip\"")
        .body(data);
  }

  public ApiResponse<Void> importConf(Upload file, HttpServletResponse response) throws Exception {
    try (var guard = ProfileOperationLock.mutation()) {
      RecentAuthentication.require();
      response.setHeader("Cache-Control", "no-store");
      service.getCaManager().loadConfAndClose(new ByteArrayInputStream(file.getBytes()));
      return ApiResponse.ok();
    }
  }

  public ApiResponse<String> getTokenInfo(String module, Integer slot, boolean verbose)
      throws CaMgmtException {
    String info = service.getCaManager().getTokenInfoP11(module, slot, verbose);
    return ApiResponse.ok(info);
  }

  public ApiResponse<Map<String, Set<String>>> getSupportedTypes() throws CaMgmtException {
    Map<String, Set<String>> types = new LinkedHashMap<>();
    if (typeVisible("SIGNER")) {
      types.put("signerTypes", service.getCaManager().getSupportedSignerTypes());
    }
    if (typeVisible("PROFILE")) {
      types.put("certprofileTypes", service.getCaManager().getSupportedCertprofileTypes());
    }
    if (typeVisible("PUBLISHER")) {
      types.put("publisherTypes", service.getCaManager().getSupportedPublisherTypes());
    }
    return ApiResponse.ok(types);
  }

  private boolean typeVisible(String resource) {
    return List.of("READ", "CREATE", "UPDATE").stream()
        .anyMatch(action -> access.has(resource + "_" + action));
  }
}
