// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api;

import org.xipki.util.Args;
import org.xipki.util.CompareUtil;
import org.xipki.util.StringUtil;

/**
 * Name and Identifier.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class NameId {

  private Integer id;

  private String name;

  // For the deserialization only
  @SuppressWarnings("unused")
  private NameId() {
  }

  public NameId(Integer id, String name) {
    this.id = id;
    this.name = Args.toNonBlankLower(name, "name");
  }

  public void setId(Integer id) {
    this.id = id;
  }

  public Integer getId() {
    return id;
  }

  public void setName(String name) {
    this.name = Args.toNonBlankLower(name, "name");
  }

  public String getName() {
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

    return CompareUtil.equalsObject(id, other.id) && name.equals(other.name);
  }

  public boolean equals(NameId obj, boolean ignoreId) {
    if (obj == null) {
      return false;
    }

    if (!name.equals(obj.name)) {
      return false;
    }

    return ignoreId || CompareUtil.equalsObject(id, obj.id);
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

}
