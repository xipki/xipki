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

package org.xipki.ca.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.*;
import org.xipki.ca.api.NameId;
import org.xipki.security.X509Cert;

import java.security.PublicKey;
import java.util.Date;
import java.util.TimeZone;

import static org.xipki.util.Args.notNull;

/**
 * X509CA module base class.
 *
 * @author Lijun Liao
 */

public abstract class X509CaModule {

  protected static final TimeZone TIMEZONE_UTC = TimeZone.getTimeZone("UTC");

  protected static final long MS_PER_SECOND = 1000L;

  protected static final long MS_PER_MINUTE = 60000L;

  protected static final long MS_PER_HOUR = 60 * MS_PER_MINUTE;

  protected static final int MINUTE_PER_DAY = 24 * 60;

  protected static final long MS_PER_DAY = MINUTE_PER_DAY * MS_PER_MINUTE;

  protected static final long MS_PER_WEEK = 7 * MS_PER_DAY;

  // CHECKSTYLE:SKIP
  protected final Logger LOG = LoggerFactory.getLogger(getClass());

  protected final NameId caIdent;

  protected final CaInfo caInfo;

  protected final X509Cert caCert;

  public X509CaModule(CaInfo caInfo) {
    this.caInfo = notNull(caInfo, "caInfo");
    this.caIdent = caInfo.getIdent();
    this.caCert = caInfo.getCert();
  } // constructor

  protected static AuditService auditService() {
    return Audits.getAuditService();
  }

  protected AuditEvent newPerfAuditEvent(String eventType, String msgId) {
    return newAuditEvent(eventType, msgId);
  }

  protected AuditEvent newAuditEvent(String eventType, String msgId) {
    notNull(eventType, "eventType");
    notNull(msgId, "msgId");
    AuditEvent event = new AuditEvent(new Date());
    event.setApplicationName(CaAuditConstants.APPNAME);
    event.setName(CaAuditConstants.NAME_perf);
    event.addEventData(CaAuditConstants.NAME_ca, caIdent.getName());
    event.addEventType(eventType);
    event.addEventData(CaAuditConstants.NAME_mid, msgId);
    return event;
  }

  protected void finish(AuditEvent event, boolean successful) {
    event.finish();
    event.setLevel(successful ? AuditLevel.INFO : AuditLevel.ERROR);
    event.setStatus(successful ? AuditStatus.SUCCESSFUL : AuditStatus.FAILED);
    auditService().logEvent(event);
  }

  protected boolean verifySignature(X509Cert cert) {
    notNull(cert, "cert");
    PublicKey caPublicKey = caCert.getPublicKey();
    try {
      cert.verify(caPublicKey);
      return true;
    } catch (Exception ex) {
      LOG.debug("{} while verifying signature: {}", ex.getClass().getName(), ex.getMessage());
      return false;
    }
  } // method verifySignature

}
