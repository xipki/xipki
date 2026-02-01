// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.NameId;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.misc.StringUtil;

/**
 * Management Entry Certificate Entry.
 * @author Lijun Liao (xipki)
 *
 */

public class CertprofileEntry extends MgmtEntry {

  private final NameId ident;

  private final String type;

  private final String conf;

  private boolean faulty;

  public CertprofileEntry(NameId ident, String type, String conf) {
    this.ident = Args.notNull(ident, "ident");
    this.type = Args.toNonBlankLower(type, "type");
    this.conf = conf;
    if ("all".equals(ident.name()) || "null".equals(ident.name())) {
      throw new IllegalArgumentException(
          "certificate profile name may not be 'all' and 'null'");
    }
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

  public boolean faulty() {
    return faulty;
  }

  public void setFaulty(boolean faulty) {
    this.faulty = faulty;
  }

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    boolean bo = (verbose || conf == null || conf.length() < 301);
    return StringUtil.concatObjectsCap(200,
        "id:     ", ident.id(), "\nname:   ", ident.name(),
        "\nfaulty: ", faulty, "\ntype:   ", type, "\nconf:   ",
        (bo ? conf : StringUtil.concat(conf.substring(0, 297), "...")));
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if  (!(obj instanceof CertprofileEntry)) {
      return false;
    }

    return equals((CertprofileEntry) obj, false);
  }

  public boolean equals(CertprofileEntry obj, boolean ignoreId) {
    if (!ident.equals(obj.ident, ignoreId)) {
      return false;
    }

    if (!type.equals(obj.type)) {
      return false;
    }

    return CompareUtil.equals(conf, obj.conf);
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

  public static CertprofileEntry parse(JsonMap json) throws CodecException {
    NameId ident = NameId.parse(json.getNnMap("ident"));
    return new CertprofileEntry(ident,
        json.getNnString("type"), json.getString("conf"));
  }

}
