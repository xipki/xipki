// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.StringUtil;

import java.security.cert.CertificateException;

/**
 * Management Entry Requestor.
 * @author Lijun Liao (xipki)
 *
 */

public class RequestorEntry extends MgmtEntry {

  /**
   * Certificate.
   */
  public static final String TYPE_CERT = "cert";

  private NameId ident;

  private String type;

  private String conf;

  private boolean faulty;

  // For the deserialization only
  @SuppressWarnings("unused")
  private RequestorEntry() {
  }

  public RequestorEntry(NameId ident, String type, String conf) {
    this.ident = Args.notNull(ident, "ident");
    String name = ident.getName();
    if (RequestorInfo.NAME_BY_CA.equals(name)) {
      throw new IllegalArgumentException("Requestor name could not be " + name);
    }

    this.type = Args.notBlank(type, "type");
    this.conf = Args.notBlank(conf, "conf");
    makeConform();
  }

  public void setIdent(NameId ident) {
    this.ident = Args.notNull(ident, "ident");
    String name = ident.getName();
    if (RequestorInfo.NAME_BY_CA.equals(name)) {
      throw new IllegalArgumentException("Requestor name could not be " + name);
    }
  }

  public void setType(String type) {
    this.type = Args.notBlank(type, "type");
    makeConform();
  }

  public void setConf(String conf) {
    this.conf = Args.notBlank(conf, "conf");
    makeConform();
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

  private void makeConform() {
    if (conf == null || !"cert".equalsIgnoreCase(type)) {
      return;
    }

    if (!conf.startsWith("LS0t")) {
      return;
    }

    try {
      byte[] binary = X509Util.toDerEncoded(Base64.decode(conf));
      conf = Base64.encodeToString(binary);
    } catch (Exception ex) {
      // do nothing
    }
  }

  public void faulty(boolean faulty) {
    this.faulty = faulty;
  }

  public boolean faulty() {
    return faulty;
  }

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    StringBuilder sb = new StringBuilder(500);
    sb.append(  "id:     ").append(ident.getId());
    sb.append("\nname:   ").append(ident.getName());
    sb.append("\ntype:   ").append(type);

    sb.append("\nconf:   ");
    if (verbose || conf.length() < 101) {
      sb.append(conf);
    } else {
      sb.append(conf, 0, 97).append("...");
    }

    sb.append("\nfaulty: ").append(faulty).append('\n');

    if (!faulty && TYPE_CERT.equalsIgnoreCase(type)) {
      sb.append("cert:\n");
      try {
        X509Cert cert = X509Util.parseCert(StringUtil.toUtf8Bytes(conf));
        sb.append(X509Util.formatCert(cert, false));
      } catch (CertificateException ex) {
        sb.append("  ERROR(").append(ex.getMessage()).append(")\n");
      }
    }

    return sb.toString();
  } // method toString(boolean)

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
