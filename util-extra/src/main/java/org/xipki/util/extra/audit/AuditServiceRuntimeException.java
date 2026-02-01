// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.audit;

/**
 * Audit Service runtime exception.
 *
 * @author Lijun Liao (xipki)
 */
public class AuditServiceRuntimeException extends RuntimeException {

  public AuditServiceRuntimeException(String message, Throwable cause) {
    super(message, cause);
  }

  public AuditServiceRuntimeException(String message) {
    super(message);
  }

}
