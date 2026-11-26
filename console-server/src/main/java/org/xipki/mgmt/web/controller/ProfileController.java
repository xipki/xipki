// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.CaManager;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.ApiResponse;
import org.xipki.mgmt.web.dto.NameTypeConfDto;
import org.xipki.mgmt.web.dto.ProfileAssociationRequest;
import org.xipki.mgmt.web.security.AccessControl;
import org.xipki.mgmt.web.service.CaManagementService;
import org.xipki.mgmt.web.service.ProfileOperationLock;

/**
 * Certificate profile management controller.
 *
 * @author palos
 */
public class ProfileController {

  private final CaManagementService service;
  private final AccessControl access;

  public ProfileController(CaManagementService service, AccessControl access) {
    this.service = service;
    this.access = access;
  }

  public ApiResponse<List<NameTypeConfDto>> listProfiles() throws CaMgmtException {
    CaManager mgr = service.getCaManager();
    Set<String> names = mgr.getCertprofileNames();
    List<NameTypeConfDto> list = new ArrayList<>();
    for (String name : names) {
      CertprofileEntry entry = mgr.getCertprofile(name);
      if (entry != null) {
        list.add(toDto(entry));
      }
    }
    return ApiResponse.ok(list);
  }

  public ApiResponse<NameTypeConfDto> getProfile(String name) throws CaMgmtException {
    CertprofileEntry entry = service.getCaManager().getCertprofile(name);
    if (entry == null) {
      throw new ApiException(404, "Resource not found");
    }
    return ApiResponse.ok(toDto(entry));
  }

  private NameTypeConfDto toDto(CertprofileEntry entry) {
    NameTypeConfDto dto = new NameTypeConfDto();
    dto.setName(entry.getIdent().getName());
    dto.setType(entry.getType());
    dto.setConf(access.has("PROFILE_CONFIG_READ") ? entry.getConf() : null);
    dto.setFaulty(entry.isFaulty());
    return dto;
  }

  public ApiResponse<Void> addProfile(NameTypeConfDto request) throws CaMgmtException {
    try (var guard = ProfileOperationLock.mutation()) {
      CertprofileEntry entry =
          new CertprofileEntry(
              new NameId(null, request.getName()), request.getType(), request.getConf());
      service.getCaManager().addCertprofile(entry);
      return ApiResponse.ok();
    }
  }

  public ApiResponse<Void> updateProfile(String name, NameTypeConfDto request)
      throws CaMgmtException {
    try (var guard = ProfileOperationLock.mutation()) {
      service.getCaManager().changeCertprofile(name, request.getType(), request.getConf());
      return ApiResponse.ok();
    }
  }

  public ApiResponse<Void> removeProfile(String name) throws CaMgmtException {
    try (var guard = ProfileOperationLock.mutation()) {
      service.getCaManager().removeCertprofile(name);
      return ApiResponse.ok();
    }
  }

  // --- CA association ---

  public ApiResponse<List<String>> getProfilesForCa(String ca, String operation)
      throws CaMgmtException {
    return ApiResponse.ok(
        operation == null ? access.allowedProfiles(ca) : access.issuanceProfiles(ca, operation));
  }

  public ApiResponse<Void> addProfileToCa(String name, String ca, ProfileAssociationRequest request)
      throws CaMgmtException {
    ca = access.require("CA_PROFILE_BIND", ca, null).name();
    String encoded = (request == null ? new ProfileAssociationRequest() : request).encoded(name);
    service.getCaManager().addCertprofileToCa(encoded, ca);
    return ApiResponse.ok();
  }

  public ApiResponse<List<Map<String, Object>>> getProfileAssociations(String ca)
      throws CaMgmtException {
    ca = access.require("CA_PROFILE_READ", ca, null).name();
    List<Map<String, Object>> result = new ArrayList<>();
    for (CaProfileEntry entry : service.getCaManager().getCertprofilesForCa(ca)) {
      result.add(
          Map.of("profileName", entry.getProfileName(), "aliases", entry.getProfileAliases()));
    }
    return ApiResponse.ok(result);
  }

  public ApiResponse<Void> removeProfileFromCa(String name, String ca) throws CaMgmtException {
    ca = access.require("CA_PROFILE_UNBIND", ca, null).name();
    service.getCaManager().removeCertprofileFromCa(name, ca);
    return ApiResponse.ok();
  }
}
