// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import java.util.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.dto.RoleRequests.Create;
import org.xipki.mgmt.web.dto.RoleRequests.Update;
import org.xipki.mgmt.web.security.*;
import org.xipki.mgmt.web.security.PermissionCatalog.Permission;

/**
 * @author palos
 */
public class RoleController {
  private final RoleService service;
  private final RoleCatalog roles;

  public RoleController(RoleService service, RoleCatalog roles) {
    this.service = service;
    this.roles = roles;
  }

  public ApiResponse<List<Map<String, Object>>> list() {
    return ApiResponse.ok(service.list());
  }

  public ApiResponse<Collection<Permission>> permissions() {
    return ApiResponse.ok(PermissionCatalog.entries());
  }

  public ApiResponse<RoleDefinition> create(Create body) {
    return ApiResponse.ok(
        service.save(
            body.name,
            null,
            body.displayName,
            body.description,
            body.scope,
            true,
            body.permissions,
            Boolean.TRUE.equals(body.confirmed)));
  }

  public ApiResponse<RoleDefinition> update(String name, Update body) {
    if (body.revision == null || body.revision < 1 || body.enabled == null) {
      throw new RoleValidationException("Missing role revision or state");
    }
    return ApiResponse.ok(
        service.save(
            name,
            body.revision,
            body.displayName,
            body.description,
            roles.find(name).scope(),
            body.enabled,
            body.permissions,
            Boolean.TRUE.equals(body.confirmed)));
  }

  public ApiResponse<Void> delete(String name, long revision) {
    service.delete(name, revision);
    return ApiResponse.ok();
  }
}
