// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.audit;

import org.xipki.util.conf.ConfPairs;
import org.xipki.util.conf.InvalidConfException;

/**
 * Audit service interface.
 *
 * @author Lijun Liao (xipki)
 */

public interface AuditService {

  int AUDIT_EVENT = 1;

  int PCI_AUDIT_EVENT = 2;

  default void init(String conf) throws InvalidConfException {
    init(new ConfPairs(conf));
  }

  void init(ConfPairs conf) throws InvalidConfException;

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

  void close() throws Exception;

}
