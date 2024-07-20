// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.xipki.util.Args;
import org.xipki.util.StringUtil;

/**
 * Identifier of a {@link P11Slot}.
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class P11SlotId {

  private final int index;

  private final long id;

  public P11SlotId(int index, long id) {
    this.index = Args.notNegative(index, "index");
    this.id = Args.notNegative(id, "id");
  }

  public int getIndex() {
    return index;
  }

  public long getId() {
    return id;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof P11SlotId)) {
      return false;
    }

    P11SlotId another = (P11SlotId) obj;
    return this.id == another.id && this.index == another.index;
  }

  @Override
  public String toString() {
    return StringUtil.concatObjectsCap(30, "(index = ", index, ", id = ", id, ")");
  }

  @Override
  public int hashCode() {
    return Long.hashCode(id) + 31 * index;
  }

}
