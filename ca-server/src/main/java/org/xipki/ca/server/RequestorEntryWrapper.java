// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import java.security.cert.CertificateException;

/**
 * Wrapper of requestor database entry.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class RequestorEntryWrapper {
  private static final Logger LOG = LoggerFactory.getLogger(RequestorEntryWrapper.class);

  private RequestorEntry dbEntry;

  private CertWithDbId cert;

  public RequestorEntryWrapper() {
  }

  public void setDbEntry(RequestorEntry dbEntry) {
    this.dbEntry = Args.notNull(dbEntry, "dbEntry");
    String type = dbEntry.getType();
    String conf = dbEntry.getConf();

    dbEntry.faulty(true);
    if (RequestorEntry.TYPE_CERT.equalsIgnoreCase(type)) {
      try {
        this.cert = new CertWithDbId(X509Util.parseCert(StringUtil.toUtf8Bytes(conf)));
        dbEntry.faulty(false);
      } catch (CertificateException ex) {
        LogUtil.error(LOG, ex, "error while parsing certificate of requestor" + dbEntry.getIdent());
      }
    }
  } // method setDbEntry

  public CertWithDbId getCert() {
    return cert;
  }

  public RequestorEntry getDbEntry() {
    return dbEntry;
  }

}
