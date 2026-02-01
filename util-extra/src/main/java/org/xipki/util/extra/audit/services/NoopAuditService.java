// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.audit.services;

import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.audit.AuditEvent;
import org.xipki.util.extra.audit.AuditService;
import org.xipki.util.extra.audit.PciAuditEvent;

/**
 * The No-Operation audit service. The events will be ignored.
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
