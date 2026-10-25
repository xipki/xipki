// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.audit.services;

import org.xipki.codec.ConfPairs;
import org.xipki.util.audit.AuditEvent;
import org.xipki.util.audit.AuditService;
import org.xipki.util.audit.PciAuditEvent;

/**
 * Noop Audit Service.
 *
 * @author Lijun Liao (xipki)
 */
public class NoopAuditService implements AuditService {

  public NoopAuditService() {
  }

  @Override
  public void init(ConfPairs conf) {
  }

  @Override
  public void logEvent(AuditEvent event) {
  }

  @Override
  public void logEvent(PciAuditEvent event) {
  }

  @Override
  public void close() {
  }

}
