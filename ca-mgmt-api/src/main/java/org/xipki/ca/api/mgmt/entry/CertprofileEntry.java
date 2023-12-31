// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.NameId;
import org.xipki.util.Args;
import org.xipki.util.CompareUtil;
import org.xipki.util.StringUtil;

/**
 * Management Entry Certificate Entry.
 * @author Lijun Liao (xipki)
 *
 */

public class CertprofileEntry extends MgmtEntry {

  private NameId ident;

  private String type;

  private String conf;

  private boolean faulty;

  // For the deserialization only
  @SuppressWarnings("unused")
  private CertprofileEntry() {
  }

  public CertprofileEntry(NameId ident, String type, String conf) {
    this.ident = Args.notNull(ident, "ident");
    this.type = Args.toNonBlankLower(type, "type");
    this.conf = conf;
    if ("all".equals(ident.getName()) || "null".equals(ident.getName())) {
      throw new IllegalArgumentException("certificate profile name may not be 'all' and 'null'");
    }
  }

  public void setIdent(NameId ident) {
    if ("all".equals(ident.getName()) || "null".equals(ident.getName())) {
      throw new IllegalArgumentException("certificate profile name may not be 'all' and 'null'");
    }
    this.ident = Args.notNull(ident, "ident");
  }

  public void setType(String type) {
    this.type = Args.toNonBlankLower(type, "type");
  }

  public void setConf(String conf) {
    this.conf = conf;
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

  public boolean isFaulty() {
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
        "id:     ", ident.getId(), "\nname:   ", ident.getName(),
        "\nfaulty: ", faulty, "\ntype:   ", type,
        "\nconf:   ", (bo ? conf : StringUtil.concat(conf.substring(0, 297), "...")));
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

    return CompareUtil.equalsObject(conf, obj.conf);
  }

  @Override
  public int hashCode() {
    return ident.hashCode();
  }

}
