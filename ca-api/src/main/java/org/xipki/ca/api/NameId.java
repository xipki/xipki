// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.misc.StringUtil;

/**
 * Name and Identifier.
 *
 * @author Lijun Liao (xipki)
 */

public class NameId implements JsonEncodable {

  private Integer id;

  private final String name;

  public NameId(Integer id, String name) {
    this.id = id;
    this.name = Args.toNonBlankLower(name, "name");
  }

  public Integer id() {
    return id;
  }

  public void setId(Integer id) {
    this.id = id;
  }

  public String name() {
    return name;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof NameId)) {
      return false;
    }

    NameId other = (NameId) obj;

    return CompareUtil.equals(id, other.id) && name.equals(other.name);
  }

  public boolean equals(NameId obj, boolean ignoreId) {
    if (obj == null) {
      return false;
    }

    if (!name.equals(obj.name)) {
      return false;
    }

    return ignoreId || CompareUtil.equals(id, obj.id);
  }

  @Override
  public int hashCode() {
    int ret = name.hashCode();
    if (id != null) {
      ret += 37 * id;
    }
    return ret;
  }

  @Override
  public String toString() {
    return StringUtil.concatObjects("(id=", id, ", name=", name, ")");
  }

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    ret.put("id", id);
    ret.put("name", name);
    return ret;
  }

  public static NameId parse(JsonMap json) throws CodecException {
    return new NameId(json.getInt("id"),
        json.getNnString("name"));
  }

}
