/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.pkcs11;

import org.xipki.util.StringUtil;

import static org.xipki.util.Args.notNegative;
import static org.xipki.util.Args.notNull;

/**
 * Identifier of a {@link P11Slot}.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11SlotIdentifier implements Comparable<P11SlotIdentifier> {

  private final int index;

  private final long id;

  public P11SlotIdentifier(int index, long id) {
    this.index = notNegative(index, "index");
    this.id = notNegative(id, "id");
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
    } else if (!(obj instanceof P11SlotIdentifier)) {
      return false;
    }

    P11SlotIdentifier another = (P11SlotIdentifier) obj;
    return this.id == another.id && this.index == another.index;
  }

  @Override
  public String toString() {
    return StringUtil.concatObjectsCap(30, "(index = ", index, ", id = ", id, ")");
  }

  @Override
  public int hashCode() {
    int hashCode = Long.hashCode(id);
    hashCode += 31 * index;
    return hashCode;
  }

  @Override
  public int compareTo(P11SlotIdentifier obj) {
    notNull(obj, "obj");
    return (this == obj)  ? 0 : Integer.signum(index - obj.index);
  }

}
