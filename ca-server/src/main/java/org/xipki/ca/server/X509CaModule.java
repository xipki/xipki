// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.sdk.CaAuditConstants;
import org.xipki.security.X509Cert;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.audit.AuditEvent;
import org.xipki.util.extra.audit.AuditLevel;
import org.xipki.util.extra.audit.AuditService;
import org.xipki.util.extra.audit.AuditStatus;
import org.xipki.util.extra.audit.Audits;

import java.util.ArrayList;
import java.util.List;

/**
 * X509CA module base class.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class X509CaModule {

  protected final Logger LOG = LoggerFactory.getLogger(getClass());

  protected final NameId caIdent;

  protected final CaInfo caInfo;

  protected final X509Cert caCert;

  protected final List<byte[]> encodedCaCertChain;

  public X509CaModule(CaInfo caInfo) {
    this.caInfo = Args.notNull(caInfo, "caInfo");
    this.caIdent = caInfo.getIdent();
    this.caCert = caInfo.getCert();
    this.encodedCaCertChain = new ArrayList<>(2);
    this.encodedCaCertChain.add(caCert.getEncoded());
    if (caInfo.getCertchain() != null) {
      for (X509Cert c : caInfo.getCertchain()) {
        this.encodedCaCertChain.add(c.getEncoded());
      }
    }
  } // constructor

  protected static AuditService auditService() {
    return Audits.getAuditService();
  }

  protected AuditEvent newAuditEvent(
      String eventType, RequestorInfo requestor) {
    Args.notNull(eventType, "eventType");
    AuditEvent event = new AuditEvent(CaAuditConstants.APPNAME);
    event.setEventData(CaAuditConstants.NAME_ca, caIdent.getName());
    event.setEventType(eventType);
    if (requestor != null) {
      event.setEventData(CaAuditConstants.NAME_requestor,
          requestor.getIdent().getName());
    }
    return event;
  }

  protected void setEventStatus(AuditEvent event, boolean successful) {
    event.setLevel(successful ? AuditLevel.INFO : AuditLevel.ERROR);
    event.setStatus(successful ? AuditStatus.SUCCESSFUL : AuditStatus.FAILED);
  }

  protected void finish(AuditEvent event, boolean successful) {
    setEventStatus(event, successful);
    event.finish();
    auditService().logEvent(event);
    event.log(LOG);
  }

  protected boolean verifySignature(X509Cert cert) {
    try {
      Args.notNull(cert, "cert").verify(caCert.getPublicKey());
      return true;
    } catch (Exception ex) {
      LOG.debug("{} while verifying signature: {}",
          ex.getClass().getName(), ex.getMessage());
      return false;
    }
  } // method verifySignature

}
