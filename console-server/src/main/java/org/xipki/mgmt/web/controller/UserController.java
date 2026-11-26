// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.dto.IdentityRequests.Bindings;
import org.xipki.mgmt.web.dto.IdentityRequests.Create;
import org.xipki.mgmt.web.dto.IdentityRequests.Status;
import org.xipki.mgmt.web.dto.IdentityRequests.Update;
import org.xipki.mgmt.web.security.*;
import org.xipki.mgmt.web.service.CaManagementService;

/**
 * @author palos
 */
public class UserController {
  private final AccountService accounts;
  private final AccessControl access;
  private final CaManagementService ca;

  public UserController(AccountService accounts, AccessControl access, CaManagementService ca) {
    this.accounts = accounts;
    this.access = access;
    this.ca = ca;
  }

  public ApiResponse<Map<String, Object>> list(String search, int page, int size) {
    return ApiResponse.ok(accounts.list(search, page, size));
  }

  public ApiResponse<Map<String, Object>> get(long id) {
    return ApiResponse.ok(accounts.get(id));
  }

  public Reply<ApiResponse<Map<String, Object>>> create(Create body) {
    return Reply.ok()
        .header("Cache-Control", "no-store")
        .body(ApiResponse.ok(accounts.create(body.username, body.displayName)));
  }

  public ApiResponse<Void> update(long id, Update body) {
    accounts.update(id, body.displayName);
    return ApiResponse.ok();
  }

  public ApiResponse<Void> status(long id, Status body) {
    if (body.enabled == null) {
      throw new IllegalArgumentException("Missing status");
    }
    accounts.setEnabled(id, body.enabled);
    return ApiResponse.ok();
  }

  public Reply<ApiResponse<Map<String, String>>> reset(long id) {
    return Reply.ok()
        .header("Cache-Control", "no-store")
        .body(ApiResponse.ok(Map.of("temporaryPassword", accounts.resetPassword(id))));
  }

  public ApiResponse<Void> revoke(long id) {
    accounts.revokeSessions(id);
    return ApiResponse.ok();
  }

  public ApiResponse<List<Map<String, Object>>> options() throws CaMgmtException {
    var result = new ArrayList<Map<String, Object>>();
    for (String name : new TreeSet<>(ca.getCaManager().getCaNames())) {
      var identity = access.identity(name);
      var profiles = ca.getCaManager().getCertprofilesForCa(identity.name());
      result.add(
          Map.of(
              "name",
              identity.name(),
              "fingerprint",
              identity.fingerprint(),
              "profiles",
              profiles == null
                  ? List.of()
                  : profiles.stream().map(p -> p.getProfileName()).sorted().toList()));
    }
    return ApiResponse.ok(result);
  }

  public ApiResponse<Void> bindings(long id, Bindings body) throws CaMgmtException {
    if (body.bindings == null || body.bindings.size() > 100) {
      throw new IllegalArgumentException("Invalid bindings");
    }
    var bindings = new ArrayList<RoleBinding>();
    for (var item : body.bindings) {
      if (item == null) {
        throw new IllegalArgumentException("Invalid binding");
      }
      String name = null, fingerprint = null;
      if ("NAMED_CA".equals(item.scope)) {
        var identity = access.identity(item.caName);
        name = identity.name();
        fingerprint = identity.fingerprint();
        if (!fingerprint.equals(item.caFingerprint)) {
          throw new IllegalArgumentException("Review current CA identity before granting access");
        }
      } else if (item.caName != null || item.caFingerprint != null) {
        throw new IllegalArgumentException("Unexpected CA");
      }
      bindings.add(
          accounts.resolveBinding(
              item.role,
              item.scope,
              name,
              fingerprint,
              Boolean.TRUE.equals(item.allProfiles),
              item.profiles));
    }
    accounts.replaceBindings(id, bindings);
    return ApiResponse.ok();
  }
}
