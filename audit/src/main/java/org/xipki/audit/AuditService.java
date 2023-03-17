// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit;

import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.exception.InvalidConfException;

/**
 * Audit service interface.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public interface AuditService extends AutoCloseable {

  int AUDIT_EVENT = 1;

  int PCI_AUDIT_EVENT = 2;

  void init(String conf);

  /**
   * @since 6.0.0
   */
  void init(String conf, PasswordResolver passwordResolver)
      throws PasswordResolverException, InvalidConfException;

  /**
   * Log audit event.
   * @param event
   *          Audit event. Must not be {@code null}-
   */
  void logEvent(AuditEvent event);

  /**
   * Log PCI audit event.
   *
   * @param event
   *          Audit event. Must not be {@code null}-
   */
  void logEvent(PciAuditEvent event);

}
