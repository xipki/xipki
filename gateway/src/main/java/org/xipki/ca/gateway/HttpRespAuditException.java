// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway;

import org.xipki.util.codec.Args;
import org.xipki.util.extra.audit.AuditLevel;
import org.xipki.util.extra.audit.AuditStatus;

/**
 * Response Audit Exception.
 *
 * @author Lijun Liao (xipki)
 */

public class HttpRespAuditException extends Exception {

  private final int httpStatus;

  private final String auditMessage;

  private final AuditLevel auditLevel;

  private final AuditStatus auditStatus;

  public HttpRespAuditException(
      int httpStatus, String auditMessage, AuditLevel auditLevel,
      AuditStatus auditStatus) {
    this.httpStatus = httpStatus;
    this.auditMessage = Args.notBlank(auditMessage, "auditMessage");
    this.auditLevel = Args.notNull(auditLevel, "auditLevel");
    this.auditStatus = Args.notNull(auditStatus, "auditStatus");
  }

  public int httpStatus() {
    return httpStatus;
  }

  public String auditMessage() {
    return auditMessage;
  }

  public AuditLevel auditLevel() {
    return auditLevel;
  }

  public AuditStatus auditStatus() {
    return auditStatus;
  }

}
