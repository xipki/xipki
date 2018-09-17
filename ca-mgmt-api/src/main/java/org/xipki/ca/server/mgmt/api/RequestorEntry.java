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

package org.xipki.ca.server.mgmt.api;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.xipki.ca.api.NameId;
import org.xipki.security.util.X509Util;
import org.xipki.util.LogUtil;

import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RequestorEntry {

  /**
   * Certificate.
   */
  public static final String TYPE_CERT = "cert";

  /**
   * Password based MAC.
   */
  public static final String TYPE_PBM = "pbm";

  private final NameId ident;

  private final String type;

  private final String conf;

  private boolean faulty;

  public RequestorEntry(NameId ident, String type, String conf) {
    this.ident = ParamUtil.requireNonNull("ident", ident);
    String name = ident.getName();
    if (RequestorInfo.NAME_BY_USER.equalsIgnoreCase(name)
        || RequestorInfo.NAME_BY_CA.equalsIgnoreCase(name)) {
      throw new IllegalArgumentException("Requestor name could not be " + name);
    }

    this.type = ParamUtil.requireNonBlank("type", type);
    this.conf = ParamUtil.requireNonBlank("conf", conf);
  }

  public NameId getIdent() {
    return ident;
  }

  public String getType() {
    return type;
  }

  public String getConf() {
    return conf;
  }

  public void setFaulty(boolean faulty) {
    this.faulty = faulty;
  }

  public boolean isFaulty() {
    return faulty;
  }

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    StringBuilder sb = new StringBuilder(500);
    sb.append("id: ").append(ident.getId());
    sb.append("\nname: ").append(ident.getName());
    sb.append("\ntype: ").append(type);

    sb.append("\nconf: ");
    if (verbose || conf.length() < 101) {
      sb.append(conf);
    } else {
      sb.append(conf.substring(0, 97)).append("...");
    }

    sb.append("\nfaulty: ").append(faulty).append('\n');

    if (!faulty && TYPE_CERT.equalsIgnoreCase(type)) {
      try {
        X509Certificate cert = X509Util.parseCert(conf.getBytes());
        sb.append("cert:");
        sb.append("\n\tissuer: ").append(X509Util.getRfc4519Name(cert.getIssuerX500Principal()));
        sb.append("\n\tserialNumber: ").append(LogUtil.formatCsn(cert.getSerialNumber()));
        sb.append("\n\tsubject: ")
          .append(X509Util.getRfc4519Name(cert.getSubjectX500Principal())).append('\n');
      } catch (CertificateException ex) {
        sb.append("cert: ERROR(").append(ex.getMessage()).append(")\n");
      }
    }

    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof RequestorEntry)) {
      return false;
    }

    return equals((RequestorEntry) obj, false);
  }

  public boolean equals(RequestorEntry obj, boolean ignoreId) {
    return (obj != null)
        && ident.equals(obj.ident, ignoreId)
        && type.equals(obj.type)
        && conf.equals(obj.conf);
  }

  @Override
  public int hashCode() {
    return ident.hashCode();
  }

}
