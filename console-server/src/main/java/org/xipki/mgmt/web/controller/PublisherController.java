// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.ApiResponse;
import org.xipki.mgmt.web.dto.EntityConfiguration;
import org.xipki.mgmt.web.dto.NameTypeConfDto;
import org.xipki.mgmt.web.security.AccessControl;
import org.xipki.mgmt.web.service.CaManagementService;

/**
 * @author palos
 */
public class PublisherController {

  private final CaManagementService service;
  private final AccessControl access;

  public PublisherController(CaManagementService service, AccessControl access) {
    this.service = service;
    this.access = access;
  }

  public ApiResponse<List<NameTypeConfDto>> listPublishers() throws CaMgmtException {
    Set<String> names = service.getCaManager().getPublisherNames();
    List<NameTypeConfDto> list = new ArrayList<>();
    for (String name : names) {
      PublisherEntry entry = service.getCaManager().getPublisher(name);
      if (entry != null) {
        list.add(toDto(entry));
      }
    }
    return ApiResponse.ok(list);
  }

  public ApiResponse<NameTypeConfDto> getPublisher(String name) throws CaMgmtException {
    PublisherEntry entry = service.getCaManager().getPublisher(name);
    if (entry == null) {
      throw new ApiException(404, "Resource not found");
    }
    return ApiResponse.ok(toDto(entry));
  }

  private static NameTypeConfDto toDto(PublisherEntry entry) {
    NameTypeConfDto dto = new NameTypeConfDto();
    dto.setName(entry.getIdent().getName());
    dto.setType(entry.getType());
    EntityConfiguration.read(dto, entry.getConf(), false);
    dto.setFaulty(entry.faulty());
    return dto;
  }

  public ApiResponse<Void> addPublisher(NameTypeConfDto request) throws CaMgmtException {
    PublisherEntry entry =
        new PublisherEntry(
            new NameId(null, request.getName()), request.getType(), request.getConf());
    service.getCaManager().addPublisher(entry);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> updatePublisher(String name, NameTypeConfDto request)
      throws CaMgmtException {
    String conf = EntityConfiguration.replacement(request);
    service.getCaManager().changePublisher(name, request.getType(), conf);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> removePublisher(String name) throws CaMgmtException {
    service.getCaManager().removePublisher(name);
    return ApiResponse.ok();
  }

  // --- CA association ---

  public ApiResponse<List<String>> getPublishersForCa(String ca) throws CaMgmtException {
    ca = access.require("CA_PUBLISHER_READ", ca, null).name();
    Set<String> names = service.getCaManager().getPublisherNamesForCa(ca);
    return ApiResponse.ok(new ArrayList<>(names));
  }

  public ApiResponse<Void> addPublisherToCa(String name, String ca) throws CaMgmtException {
    ca = access.require("CA_PUBLISHER_BIND", ca, null).name();
    service.getCaManager().addPublisherToCa(name, ca);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> removePublisherFromCa(String name, String ca) throws CaMgmtException {
    ca = access.require("CA_PUBLISHER_UNBIND", ca, null).name();
    service.getCaManager().removePublisherFromCa(name, ca);
    return ApiResponse.ok();
  }
}
