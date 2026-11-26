// License Apache License 2.0

package org.xipki.mgmt.web.audit;

import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public record AuditEvent(
    String actorUsername,
    Long actorUserId,
    String sourceIp,
    String requestId,
    String httpMethod,
    String requestPath,
    String action,
    String result,
    String failureCategory,
    long durationMs,
    String resourceType,
    String resourceId,
    String permissionCodes) {
  public AuditEvent(
      String actorUsername,
      Long actorUserId,
      String sourceIp,
      String requestId,
      String httpMethod,
      String requestPath,
      String action,
      String result,
      String failureCategory,
      long durationMs,
      String resourceType,
      String resourceId) {
    this(
        actorUsername,
        actorUserId,
        sourceIp,
        requestId,
        httpMethod,
        requestPath,
        action,
        result,
        failureCategory,
        durationMs,
        resourceType,
        resourceId,
        null);
  }

  public AuditEvent(
      String actorUsername,
      Long actorUserId,
      String sourceIp,
      String requestId,
      String httpMethod,
      String requestPath,
      String action,
      String result,
      String failureCategory,
      long durationMs) {
    this(
        actorUsername,
        actorUserId,
        sourceIp,
        requestId,
        httpMethod,
        requestPath,
        action,
        result,
        failureCategory,
        durationMs,
        null,
        null,
        null);
  }
}
