// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit.services;

import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditService;
import org.xipki.audit.PciAuditEvent;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;

/**
 * The No-Operation audit service. The events will be ignored.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class NoopAuditService implements AuditService {

  public NoopAuditService() {
  }

  @Override
  public void init(String conf) {
  }

  @Override
  public void init(String conf, PasswordResolver passwordResolver)
      throws PasswordResolverException {
  }

  @Override
  public void logEvent(AuditEvent event) {
  }

  @Override
  public void logEvent(PciAuditEvent event) {
  }

  @Override
  public void close() throws Exception {
  }

}
