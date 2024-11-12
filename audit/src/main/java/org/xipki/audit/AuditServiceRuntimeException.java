// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit;

/**
 * Audit Service runtime exception.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
public class AuditServiceRuntimeException extends RuntimeException {

  public AuditServiceRuntimeException(String message, Throwable cause) {
    super(message, cause);
  }

  public AuditServiceRuntimeException(String message) {
    super(message);
  }

}
