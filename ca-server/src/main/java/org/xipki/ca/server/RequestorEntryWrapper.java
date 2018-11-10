/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.mgmt.api.RequestorEntry;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.X509Util;
import org.xipki.util.LogUtil;
import org.xipki.util.ParamUtil;

/**
 * TODO.
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
    this.dbEntry = ParamUtil.requireNonNull("dbEntry", dbEntry);
    String type = dbEntry.getType();
    String conf = dbEntry.getConf();

    dbEntry.setFaulty(true);
    if (RequestorEntry.TYPE_CERT.equalsIgnoreCase(type)) {
      try {
        X509Certificate x509Cert = X509Util.parseCert(conf.getBytes());
        dbEntry.setFaulty(false);
        this.cert = new CertWithDbId(x509Cert);
      } catch (CertificateException ex) {
        LogUtil.error(LOG, ex, "error while parsing certificate of requestor" + dbEntry.getIdent());
      }
    } else if (RequestorEntry.TYPE_PBM.equalsIgnoreCase(type)) {
      try {
        this.keyId = HashAlgo.SHA1.hash(dbEntry.getIdent().getName().getBytes("UTF-8"));
        this.password = passwordResolver.resolvePassword(conf);
        dbEntry.setFaulty(false);
      } catch (PasswordResolverException | UnsupportedEncodingException ex) {
        LogUtil.error(LOG, ex, "error while resolve password of requestor" + dbEntry.getIdent());
      }
    }
  }

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
