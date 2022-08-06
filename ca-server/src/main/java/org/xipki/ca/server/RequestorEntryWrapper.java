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
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import java.security.cert.CertificateException;
import java.util.Arrays;

/**
 * Wrapper of requestor database entry.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RequestorEntryWrapper {
  private static final Logger LOG = LoggerFactory.getLogger(RequestorEntryWrapper.class);

  private RequestorEntry dbEntry;

  private CertWithDbId cert;

  private byte[] keyId;

  private char[] password;

  public RequestorEntryWrapper() {
  }

  public void setDbEntry(RequestorEntry dbEntry, PasswordResolver passwordResolver) {
    this.dbEntry = Args.notNull(dbEntry, "dbEntry");
    String type = dbEntry.getType();
    String conf = dbEntry.getConf();

    dbEntry.setFaulty(true);
    if (RequestorEntry.TYPE_CERT.equalsIgnoreCase(type)) {
      try {
        X509Cert x509Cert = X509Util.parseCert(StringUtil.toUtf8Bytes(conf));
        dbEntry.setFaulty(false);
        this.cert = new CertWithDbId(x509Cert);
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

  public boolean matchKeyId(byte[] keyId) {
    return Arrays.equals(keyId, this.keyId);
  }

  public char[] getPassword() {
    return password;
  }

}
