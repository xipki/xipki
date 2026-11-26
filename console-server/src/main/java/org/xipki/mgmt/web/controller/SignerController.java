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
public class SignerController {

  private final CaManagementService service;

  public SignerController(CaManagementService service) {
    this.service = service;
  }

  public ApiResponse<List<NameTypeConfDto>> listSigners() throws CaMgmtException {
    Set<String> names = service.getCaManager().getSignerNames();
    List<NameTypeConfDto> list = new ArrayList<>();
    for (String name : names) {
      SignerEntry entry = service.getCaManager().getSigner(name);
      if (entry != null) {
        list.add(toDto(entry));
      }
    }
    return ApiResponse.ok(list);
  }

  public ApiResponse<NameTypeConfDto> getSigner(String name) throws CaMgmtException {
    SignerEntry entry = service.getCaManager().getSigner(name);
    if (entry == null) {
      throw new ApiException(404, "Resource not found");
    }
    return ApiResponse.ok(toDto(entry));
  }

  private static NameTypeConfDto toDto(SignerEntry entry) {
    NameTypeConfDto dto = new NameTypeConfDto();
    dto.setName(entry.getName());
    dto.setType(entry.getType());
    EntityConfiguration.read(dto, entry.getConf(), false);
    dto.setFaulty(entry.isFaulty());
    dto.setBase64Cert(entry.base64Cert());
    return dto;
  }

  public ApiResponse<Void> addSigner(NameTypeConfDto request) throws CaMgmtException {
    SignerEntry entry =
        new SignerEntry(
            request.getName(), request.getType(), request.getConf(), request.getBase64Cert());
    service.getCaManager().addSigner(entry);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> updateSigner(String name, NameTypeConfDto request)
      throws CaMgmtException {
    String conf = EntityConfiguration.replacement(request);
    service.getCaManager().changeSigner(name, request.getType(), conf, request.getBase64Cert());
    return ApiResponse.ok();
  }

  public ApiResponse<Void> removeSigner(String name) throws CaMgmtException {
    service.getCaManager().removeSigner(name);
    return ApiResponse.ok();
  }
}
