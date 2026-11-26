// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import java.util.Map;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.ApiResponse;
import org.xipki.mgmt.web.service.CaManagementService;

/**
 * @author palos
 */
public class DbSchemaController {

  private final CaManagementService service;

  public DbSchemaController(CaManagementService service) {
    this.service = service;
  }

  public ApiResponse<Map<String, String>> listDbSchemas() throws CaMgmtException {
    return ApiResponse.ok(service.getCaManager().getDbSchemas());
  }

  public ApiResponse<Void> addDbSchema(Map<String, String> request) throws CaMgmtException {
    service.getCaManager().addDbSchema(request.get("name"), request.get("value"));
    return ApiResponse.ok();
  }

  public ApiResponse<Void> updateDbSchema(String name, Map<String, String> request)
      throws CaMgmtException {
    service.getCaManager().changeDbSchema(name, request.get("value"));
    return ApiResponse.ok();
  }

  public ApiResponse<Void> removeDbSchema(String name) throws CaMgmtException {
    service.getCaManager().removeDbSchema(name);
    return ApiResponse.ok();
  }
}
