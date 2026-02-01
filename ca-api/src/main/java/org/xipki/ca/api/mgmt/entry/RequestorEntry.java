// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.misc.StringUtil;

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

  private final NameId ident;

  private final String type;

  private final String conf;

  private boolean faulty;

  public RequestorEntry(NameId ident, String type, String conf) {
    this.ident = Args.notNull(ident, "ident");
    String name = ident.name();
    if (RequestorInfo.NAME_BY_CA.equals(name)) {
      throw new IllegalArgumentException("Requestor name could not be " + name);
    }

    this.type = Args.notBlank(type, "type");

    Args.notBlank(conf, "conf");
    if ("cert".equalsIgnoreCase(type) && conf.startsWith("LS0t")) {
      try {
        byte[] binary = X509Util.toDerEncoded(Base64.decode(conf));
        conf = Base64.encodeToString(binary);
      } catch (Exception ex) {
        // do nothing
      }
    }

    this.conf = conf;
  }

  public NameId ident() {
    return ident;
  }

  public String type() {
    return type;
  }

  public String conf() {
    return conf;
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
    sb.append(  "id:     ").append(ident.id());
    sb.append("\nname:   ").append(ident.name());
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

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("ident", ident.toCodec())
        .put("type", type).put("conf", conf);
  }

  public static RequestorEntry parse(JsonMap json) throws CodecException {
    return new RequestorEntry(NameId.parse(json.getNnMap("ident")),
        json.getNnString("type"), json.getString("conf"));
  }

}
