// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.ApiResponse;
import org.xipki.mgmt.web.dto.EntityConfiguration;
import org.xipki.mgmt.web.dto.NameTypeConfDto;
import org.xipki.mgmt.web.dto.RequestorAssociationRequest;
import org.xipki.mgmt.web.security.AccessControl;
import org.xipki.mgmt.web.service.CaManagementService;

/**
 * @author palos
 */
public class RequestorController {

  private final CaManagementService service;
  private final AccessControl access;

  public RequestorController(CaManagementService service, AccessControl access) {
    this.service = service;
    this.access = access;
  }

  public ApiResponse<List<NameTypeConfDto>> listRequestors() throws CaMgmtException {
    Set<String> names = service.getCaManager().getRequestorNames();
    List<NameTypeConfDto> list = new ArrayList<>();
    for (String name : names) {
      RequestorEntry entry = service.getCaManager().getRequestor(name);
      if (entry != null) {
        list.add(toDto(entry));
      }
    }
    return ApiResponse.ok(list);
  }

  public ApiResponse<NameTypeConfDto> getRequestor(String name) throws CaMgmtException {
    RequestorEntry entry = service.getCaManager().getRequestor(name);
    if (entry == null) {
      throw new ApiException(404, "Resource not found");
    }
    return ApiResponse.ok(toDto(entry));
  }

  private static NameTypeConfDto toDto(RequestorEntry entry) {
    NameTypeConfDto dto = new NameTypeConfDto();
    dto.setName(entry.getIdent().getName());
    dto.setType(entry.getType());
    EntityConfiguration.read(dto, entry.getConf(), "cert".equalsIgnoreCase(entry.getType()));
    dto.setFaulty(entry.faulty());
    return dto;
  }

  public ApiResponse<Void> addRequestor(NameTypeConfDto request) throws CaMgmtException {
    RequestorEntry entry =
        new RequestorEntry(
            new NameId(null, request.getName()), request.getType(), request.getConf());
    service.getCaManager().addRequestor(entry);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> updateRequestor(String name, NameTypeConfDto request)
      throws CaMgmtException {
    CaManager manager = service.getCaManager();
    RequestorEntry current = manager.getRequestor(name);
    if (current == null) {
      throw new ApiException(404, "Resource not found");
    }
    String type = request.getType() == null ? current.getType() : request.getType();
    boolean sameType = type.equalsIgnoreCase(current.getType());
    boolean publicConf = "cert".equalsIgnoreCase(current.getType()) && sameType;
    String conf;
    if (publicConf && request.getConf() != null && !request.isReplaceConf()) {
      EntityConfiguration.requireComplete(request.getConf());
      conf = request.getConf();
    } else {
      conf = EntityConfiguration.replacement(request);
    }
    if (conf == null) {
      if (!sameType) {
        throw new IllegalArgumentException("Type change requires complete configuration");
      }
      return ApiResponse.ok();
    }
    manager.changeRequestor(name, type, conf);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> removeRequestor(String name) throws CaMgmtException {
    service.getCaManager().removeRequestor(name);
    return ApiResponse.ok();
  }

  // --- CA association ---

  public ApiResponse<List<Map<String, Object>>> getRequestorsForCa(String ca)
      throws CaMgmtException {
    var identity = access.require("CA_REQUESTOR_READ", ca, null);
    ca = identity.name();
    boolean showAccess = access.allows("CA_REQUESTOR_ACCESS_READ", identity, null);
    Set<CaHasRequestorEntry> entries = service.getCaManager().getRequestorsForCa(ca);
    List<Map<String, Object>> result = new ArrayList<>();
    for (CaHasRequestorEntry entry : entries) {
      Map<String, Object> item = new LinkedHashMap<>();
      item.put("requestorName", entry.getRequestorIdent().getName());
      if (showAccess) {
        item.put("permissions", entry.getPermissions().toPermissionTexts());
        item.put("profiles", entry.getProfiles());
      }
      result.add(item);
    }
    return ApiResponse.ok(result);
  }

  public ApiResponse<Void> addRequestorToCa(
      String name, String ca, RequestorAssociationRequest request) throws CaMgmtException {
    ca = access.require("CA_REQUESTOR_BIND", ca, null).name();
    access.require("CA_REQUESTOR_ACCESS_UPDATE", ca, null);
    CaHasRequestorEntry entry = request.entry(name);
    service.getCaManager().addRequestorToCa(entry, ca);
    return ApiResponse.ok();
  }

  /** XiPKI has no atomic association update. Never replay or pretend to roll back this sequence. */
  public Reply<ApiResponse<Void>> updateRequestorForCa(
      String name, String ca, RequestorAssociationRequest request) throws CaMgmtException {
    ca = access.require("CA_REQUESTOR_ACCESS_UPDATE", ca, null).name();
    if (!request.isConfirmNonAtomic()) {
      throw new IllegalArgumentException("Non-atomic change requires confirmation");
    }
    CaHasRequestorEntry replacement = request.entry(name);
    CaManager manager = service.getCaManager();
    boolean exists =
        manager.getRequestorsForCa(ca).stream()
            .anyMatch(entry -> entry.getRequestorIdent().getName().equalsIgnoreCase(name));
    if (!exists) {
      return Reply.status(404).body(ApiResponse.error("Requestor association not found"));
    }
    try {
      manager.removeRequestorFromCa(name, ca);
    } catch (CaMgmtException ex) {
      return Reply.status(409)
          .body(
              ApiResponse.error(
                  "Association removal failed; its state may have changed. Refresh and verify"
                      + " before trying again."));
    }
    try {
      manager.addRequestorToCa(replacement, ca);
    } catch (CaMgmtException ex) {
      return Reply.status(409)
          .body(
              ApiResponse.error(
                  "Previous association removed; replacement failed or its result is unknown."
                      + " Refresh and verify before rebinding. No rollback was attempted."));
    }
    return Reply.ok(ApiResponse.ok());
  }

  public ApiResponse<Void> removeRequestorFromCa(String name, String ca) throws CaMgmtException {
    ca = access.require("CA_REQUESTOR_UNBIND", ca, null).name();
    service.getCaManager().removeRequestorFromCa(name, ca);
    return ApiResponse.ok();
  }
}
