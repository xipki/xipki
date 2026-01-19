// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt.entry;

import org.xipki.ca.api.NameId;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.misc.StringUtil;

/**
 * Management Entry Publisher.
 * @author Lijun Liao (xipki)
 *
 */

public class PublisherEntry extends MgmtEntry {

  private final NameId ident;

  private final String type;

  private final String conf;

  private boolean faulty;

  public PublisherEntry(NameId ident, String type, String conf) {
    this.ident = Args.notNull(ident, "ident");
    this.type = Args.toNonBlankLower(type, "type");
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

  public boolean faulty() {
    return faulty;
  }

  public void faulty(boolean faulty) {
    this.faulty = faulty;
  }

  @Override
  public String toString() {
    return StringUtil.concatObjectsCap(200,
        "id:     ", ident.getId(), "\nname:   ", ident.getName(),
        "\nfaulty: ", faulty, "\ntype:   ", type, "\nconf:   ", conf);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof PublisherEntry)) {
      return false;
    }

    return equals((PublisherEntry) obj, false);
  }

  public boolean equals(PublisherEntry obj, boolean ignoreId) {
    return (obj != null)
        && ident.equals(obj.ident, ignoreId)
        && type.equals(obj.type)
        && CompareUtil.equals(conf, obj.conf);
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

  public static PublisherEntry parse(JsonMap json) throws CodecException {
    return new PublisherEntry(
        NameId.parse(json.getNnMap("ident")),
        json.getNnString("type"), json.getString("conf"));
  }

}
