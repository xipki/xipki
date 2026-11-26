// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.ApiResponse;
import org.xipki.mgmt.web.dto.EntityConfiguration;
import org.xipki.mgmt.web.dto.NameTypeConfDto;
import org.xipki.mgmt.web.service.CaManagementService;

/**
 * @author palos
 */
public class KeypairGenController {

  private final CaManagementService service;

  public KeypairGenController(CaManagementService service) {
    this.service = service;
  }

  public ApiResponse<List<NameTypeConfDto>> listKeypairGens() throws CaMgmtException {
    Set<String> names = service.getCaManager().getKeypairGenNames();
    List<NameTypeConfDto> list = new ArrayList<>();
    for (String name : names) {
      KeypairGenEntry entry = service.getCaManager().getKeypairGen(name);
      if (entry != null) {
        list.add(toDto(entry));
      }
    }
    return ApiResponse.ok(list);
  }

  public ApiResponse<NameTypeConfDto> getKeypairGen(String name) throws CaMgmtException {
    KeypairGenEntry entry = service.getCaManager().getKeypairGen(name);
    if (entry == null) {
      throw new ApiException(404, "Resource not found");
    }
    return ApiResponse.ok(toDto(entry));
  }

  private static NameTypeConfDto toDto(KeypairGenEntry entry) {
    NameTypeConfDto dto = new NameTypeConfDto();
    dto.setName(entry.getName());
    dto.setType(entry.getType());
    EntityConfiguration.read(dto, entry.getConf(), false);
    dto.setFaulty(entry.faulty());
    return dto;
  }

  public ApiResponse<Void> addKeypairGen(NameTypeConfDto request) throws CaMgmtException {
    KeypairGenEntry entry =
        new KeypairGenEntry(request.getName(), request.getType(), request.getConf());
    service.getCaManager().addKeypairGen(entry);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> updateKeypairGen(String name, NameTypeConfDto request)
      throws CaMgmtException {
    String conf = EntityConfiguration.replacement(request);
    service.getCaManager().changeKeypairGen(name, request.getType(), conf);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> removeKeypairGen(String name) throws CaMgmtException {
    service.getCaManager().removeKeypairGen(name);
    return ApiResponse.ok();
  }
}
