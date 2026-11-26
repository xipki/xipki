// License Apache License 2.0

package org.xipki.mgmt.web.controller;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import org.xipki.mgmt.web.audit.AuditCsv;
import org.xipki.mgmt.web.audit.AuditService;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.ApiResponse;

/**
 * @author palos
 */
public class AuditController {
  private final AuditService auditService;

  public AuditController(AuditService auditService) {
    this.auditService = auditService;
  }

  public ApiResponse<Map<String, Object>> list(
      int page,
      int size,
      String actor,
      String action,
      String result,
      Instant from,
      Instant to,
      String resourceType,
      String resourceId) {
    int safePage = Math.max(0, page);
    int safeSize = Math.min(200, Math.max(1, size));
    if (from != null && to != null && from.isAfter(to)) {
      throw new IllegalArgumentException("Invalid time range");
    }
    var rows =
        auditService.query(
            safePage, safeSize, actor, action, result, from, to, resourceType, resourceId);
    return ApiResponse.ok(
        Map.of(
            "items",
            rows.subList(0, Math.min(safeSize, rows.size())),
            "page",
            safePage,
            "size",
            safeSize,
            "hasMore",
            rows.size() > safeSize));
  }

  public Reply<byte[]> export(
      String actor,
      String action,
      String result,
      Instant from,
      Instant to,
      String resourceType,
      String resourceId) {
    if (from != null && to != null && from.isAfter(to)) {
      throw new IllegalArgumentException("Invalid time range");
    }
    var rows =
        auditService.query(0, 5000, actor, action, result, from, to, resourceType, resourceId);
    byte[] data =
        AuditCsv.encode(rows.subList(0, Math.min(5000, rows.size())))
            .getBytes(StandardCharsets.UTF_8);
    return Reply.ok()
        .header("Cache-Control", "no-store")
        .header("Content-Disposition", "attachment; filename=\"xipki-audit.csv\"")
        .header("X-Export-Truncated", Boolean.toString(rows.size() > 5000))
        .contentType("text/csv;charset=UTF-8")
        .body(data);
  }

  public ApiResponse<Map<String, Object>> context(int page) {
    if (page < 0) {
      throw new IllegalArgumentException("Invalid page");
    }
    return ApiResponse.ok(auditService.authorizationContext(page));
  }
}
