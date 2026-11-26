// License Apache License 2.0

package org.xipki.mgmt.web;

import java.time.DateTimeException;
import java.time.Instant;
import java.util.*;
import org.xipki.mgmt.web.controller.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.*;
import org.xipki.mgmt.web.dto.IdentityRequests.Bindings;
import org.xipki.mgmt.web.dto.IdentityRequests.Create;
import org.xipki.mgmt.web.dto.IdentityRequests.Password;
import org.xipki.mgmt.web.dto.IdentityRequests.Reauth;
import org.xipki.mgmt.web.dto.IdentityRequests.Status;
import org.xipki.mgmt.web.dto.IdentityRequests.Update;
import org.xipki.mgmt.web.security.SessionManager;

/**
 * Auditable, explicit identity routes. All API paths also pass ManagementApiPolicy.
 *
 * @author palos
 */
public final class IdentityRoutes {
  private final AuthController auth;
  private final UserController users;
  private final RoleController roles;
  private final AuditController audit;
  private final SessionManager sessions;

  public IdentityRoutes(
      AuthController auth,
      UserController users,
      RoleController roles,
      AuditController audit,
      SessionManager sessions) {
    this.auth = auth;
    this.users = users;
    this.roles = roles;
    this.audit = audit;
    this.sessions = sessions;
  }

  public void register(Routes routes) {
    routes.add(
        "GET",
        "/api/auth/csrf",
        r -> {
          r.resp().setHeader("Cache-Control", "no-store");
          return Map.of("token", sessions.csrf(r.req(), r.resp()), "headerName", "X-CSRF-TOKEN");
        });
    routes.add(
        "POST",
        "/api/auth/login",
        r -> {
          Map<?, ?> raw = r.body(Map.class);
          if (!raw.keySet().stream().allMatch(k -> Set.of("username", "password").contains(k))
              || !(raw.get("username") instanceof String username)
              || !(raw.get("password") instanceof String password)) {
            throw new ApiException(401, "Invalid credentials");
          }
          return auth.login(Map.of("username", username, "password", password), r.req(), r.resp());
        });
    routes.add("GET", "/api/auth/methods", r -> auth.methods());
    routes.add(
        "POST", "/api/auth/certificate", r -> auth.certificate(r.req(), r.resp()));
    routes.add("GET", "/api/auth/me", r -> auth.currentUser());
    routes.add(
        "POST",
        "/api/auth/password",
        r -> auth.password(r.body(Password.class), r.req(), r.resp()));
    routes.add(
        "POST", "/api/auth/reauth", r -> auth.reauth(r.body(Reauth.class), r.req(), r.resp()));
    routes.add("POST", "/api/auth/logout", r -> auth.logout(r.req(), r.resp()));
    routes.add("PUT", "/api/auth/profile", r -> auth.profile(r.body(Update.class), r.resp()));
    routes.add(
        "GET",
        "/api/users",
        r -> users.list(r.param("search", ""), r.integer("page", 0), r.integer("size", 25)));
    routes.add("GET", "/api/users/{id}", r -> users.get(id(r.path("id"))));
    routes.add("POST", "/api/users", r -> users.create(r.body(Create.class)));
    routes.add("PUT", "/api/users/{id}", r -> users.update(id(r.path("id")), r.body(Update.class)));
    routes.add(
        "POST",
        "/api/users/{id}/status",
        r -> users.status(id(r.path("id")), r.body(Status.class)));
    routes.add("POST", "/api/users/{id}/reset-password", r -> users.reset(id(r.path("id"))));
    routes.add("POST", "/api/users/{id}/sessions/revoke", r -> users.revoke(id(r.path("id"))));
    routes.add(
        "PUT",
        "/api/users/{id}/role-bindings",
        r -> users.bindings(id(r.path("id")), r.body(Bindings.class)));
    // RoleRequests also defines Create and Update, so those route types retain their qualifier.
    routes.add("GET", "/api/access-options", r -> users.options());
    routes.add("GET", "/api/roles", r -> roles.list());
    routes.add("GET", "/api/permissions", r -> roles.permissions());
    routes.add("POST", "/api/roles", r -> roles.create(r.body(RoleRequests.Create.class)));
    routes.add(
        "PUT",
        "/api/roles/{name}",
        r -> roles.update(r.path("name"), r.body(RoleRequests.Update.class)));
    routes.add(
        "DELETE",
        "/api/roles/{name}",
        r -> roles.delete(r.path("name"), id(r.required("revision"))));
    routes.add(
        "GET",
        "/api/audit",
        r ->
            audit.list(
                r.integer("page", 0),
                r.integer("size", 50),
                r.param("actor"),
                r.param("action"),
                r.param("result"),
                instant(r.param("from")),
                instant(r.param("to")),
                r.param("resourceType"),
                r.param("resourceId")));
    routes.add(
        "GET",
        "/api/audit/export",
        r ->
            audit.export(
                r.param("actor"),
                r.param("action"),
                r.param("result"),
                instant(r.param("from")),
                instant(r.param("to")),
                r.param("resourceType"),
                r.param("resourceId")));
    routes.add("GET", "/api/audit/context", r -> audit.context(r.integer("page", 0)));
  }

  private static long id(String value) {
    try {
      long id = Long.parseLong(value);
      if (id < 1) {
        throw new NumberFormatException();
      }
      return id;
    } catch (NumberFormatException ex) {
      throw new IllegalArgumentException("Invalid identity or revision");
    }
  }

  private static Instant instant(String value) {
    if (value == null) {
      return null;
    }
    try {
      return Instant.parse(value);
    } catch (DateTimeException ex) {
      throw new IllegalArgumentException("Invalid timestamp");
    }
  }
}
