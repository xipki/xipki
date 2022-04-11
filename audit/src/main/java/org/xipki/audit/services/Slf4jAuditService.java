/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.audit.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.PciAuditEvent;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;

/**
 * The embedded audit service. It uses Log4j logger xipki.audit.sl4fj.
 *
 * @author Lijun Liao
 * @since 2.0.0
 * @deprecated Use {@link EmbedAuditService instead.
 */

public class Slf4jAuditService implements AuditService {

  private static final Logger LOG = LoggerFactory.getLogger("xipki.audit.slf4j");

  private static final Marker MARKER =  MarkerFactory.getMarker("xiaudit");

  public Slf4jAuditService() {
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
    if (LOG.isInfoEnabled()) {
      LOG.info(MARKER, "{} | {} | {}",
              event.getLevel().getText(), AuditService.AUDIT_EVENT, event.toTextMessage());
    }
  } // method logEvent

  @Override
  public void logEvent(PciAuditEvent event) {
    AuditLevel al = event.getLevel();
    if (LOG.isInfoEnabled()) {
      LOG.info(MARKER, "{} | {} | {}",
              al.getText(), AuditService.PCI_AUDIT_EVENT, event.toTextMessage());
    }
  } // method logEvent

  @Override
  public void close() throws Exception {
  }

}
