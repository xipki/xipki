// License Apache License 2.0

package org.xipki.mgmt.web.audit;

import jakarta.servlet.http.HttpServletRequest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.security.AccountService;
import org.xipki.mgmt.web.security.ManagementApiPolicy;

/**
 * @author palos
 */
public class AuditService {
  private final Jdbc jdbcTemplate;

  public AuditService(Jdbc jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  public void record(AuditEvent event) {
    jdbcTemplate.update(
        """
        INSERT INTO web_audit_event(actor_user_id, actor_username, source_ip, request_id,
          http_method, request_path, action, result, failure_category, duration_ms,
          resource_type,resource_id,permission_codes)
        VALUES (COALESCE(?, (SELECT id FROM web_user WHERE username=?)),
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)
        """,
        event.actorUserId(),
        limit(event.actorUsername(), 128),
        limit(event.actorUsername(), 128),
        limit(event.sourceIp(), 64),
        limit(event.requestId(), 128),
        limit(event.httpMethod(), 16),
        limit(event.requestPath(), 512),
        limit(event.action(), 128),
        limit(event.result(), 32),
        limit(event.failureCategory(), 128),
        event.durationMs(),
        limit(event.resourceType(), 128),
        limit(event.resourceId(), 255),
        event.permissionCodes());
  }

  /** Called inside the identity mutation's transaction; never receives passwords or hashes. */
  public void identityChange(String action, long targetId, Object before, Object after) {
    authorizationChange(action, "user", Long.toString(targetId), before, after);
  }

  public void authorizationChange(
      String action, String resourceType, String resourceId, Object before, Object after) {
    var actor = AccountService.principal();
    HttpServletRequest http = RequestContext.request();
    var details = new LinkedHashMap<String, Object>();
    details.put("before", before);
    details.put("after", after);
    String json = Json.write(details);
    String permissions = http == null ? "" : ManagementApiPolicy.permissionCodes(http);
    if (permissions.isEmpty()) {
      permissions =
          switch (action) {
            case "USER_CREATE", "USER_UPDATE" -> action;
            case "USER_ENABLE", "USER_DISABLE" -> "USER_STATUS_UPDATE";
            case "PASSWORD_RESET" -> "USER_PASSWORD_RESET";
            case "SESSIONS_REVOKE" -> "USER_SESSION_REVOKE";
            case "ROLE_BINDINGS_REPLACE" -> "USER_ROLE_ASSIGN";
            case "ROLE_CREATE", "ROLE_UPDATE", "ROLE_DELETE" -> "ROLE_MANAGE";
            default -> "";
          };
    }
    jdbcTemplate.update(
        """
        INSERT INTO web_audit_event(actor_user_id,actor_username,source_ip,request_id,
          http_method,request_path,
          resource_type,resource_id,action,result,details_json,permission_codes)
        VALUES (?,?,?,?,?,?,?,?,?,'SUCCESS',?,?)
        """,
        actor.id(),
        actor.getUsername(),
        http == null ? null : http.getRemoteAddr(),
        http == null ? null : http.getAttribute(RequestIdFilter.ATTRIBUTE),
        http == null ? null : http.getMethod(),
        http == null ? null : http.getRequestURI(),
        resourceType,
        resourceId,
        action,
        json,
        permissions);
  }

  public List<Map<String, Object>> query(
      int page, int size, String actor, String action, String result) {
    return query(page, size, actor, action, result, null, null, null, null);
  }

  public List<Map<String, Object>> query(
      int page,
      int size,
      String actor,
      String action,
      String result,
      Instant from,
      Instant to,
      String resourceType,
      String resourceId) {
    StringBuilder sql =
        new StringBuilder(
            "SELECT"
                + " id,event_time,actor_user_id,actor_username,source_ip,request_id,"
                + "http_method,request_path,resource_type,resource_id,action,result,"
                + "failure_category,duration_ms,details_json,permission_codes"
                + " FROM web_audit_event WHERE 1=1");
    List<Object> args = new ArrayList<>();
    if (actor != null && !actor.isBlank()) {
      sql.append(" AND actor_username=?");
      args.add(actor);
    }
    if (action != null && !action.isBlank()) {
      sql.append(" AND action=?");
      args.add(action);
    }
    if (result != null && !result.isBlank()) {
      sql.append(" AND result=?");
      args.add(result);
    }
    if (from != null) {
      sql.append(" AND event_time>=?");
      args.add(Timestamp.from(from));
    }
    if (to != null) {
      sql.append(" AND event_time<=?");
      args.add(Timestamp.from(to));
    }
    if (resourceType != null && !resourceType.isBlank()) {
      sql.append(" AND resource_type=?");
      args.add(resourceType);
    }
    if (resourceId != null && !resourceId.isBlank()) {
      sql.append(" AND resource_id=?");
      args.add(resourceId);
    }
    sql.append(" ORDER BY event_time DESC, id DESC LIMIT ? OFFSET ?");
    args.add(size + 1);
    args.add((long) page * size);
    return jdbcTemplate.queryForList(sql.toString(), args.toArray());
  }

  private static String limit(String value, int length) {
    return value == null ? null : value.substring(0, Math.min(value.length(), length));
  }

  public Map<String, Object> authorizationContext(int page) {
    var rows =
        jdbcTemplate.queryForList(
            """
            SELECT u.id,u.username,u.display_name,u.enabled,b.role_name,b.scope_type,
                   b.ca_name,b.ca_fingerprint,
                   b.all_profiles,p.profile_name
            FROM web_user u LEFT JOIN web_role_binding b ON b.user_id=u.id
            LEFT JOIN web_binding_profile p ON p.binding_id=b.id
            ORDER BY u.id,b.id,p.profile_name LIMIT 201 OFFSET ?
            """,
            (long) page * 200);
    return Map.of(
        "items",
        rows.subList(0, Math.min(200, rows.size())),
        "hasMore",
        rows.size() > 200,
        "page",
        page);
  }
}
