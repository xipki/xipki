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

import org.xipki.util.Args;
import org.xipki.util.CompareUtil;
import org.xipki.util.Hex;

import java.util.Arrays;

import static org.xipki.util.Args.notNull;

/**
 * Identifier of a PKCS#11 Object.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11ObjectId implements Comparable<P11ObjectId> {

  private final long handle;

  private final byte[] id;

  private final String idHex;

  private final String label;

  /**
   * Constructor.
   *
   * @param id
   *          Identifier. Cannot be null or zero-length if label is {@code null} or blank.
   * @param label
   *          Label. Cannot be {@code null} and blank if id is null or zero-length.
   */
  public P11ObjectId(long handle, byte[] id, String label) {
    this.handle = handle;
    if (id == null || id.length == 0) {
      this.id = null;
      this.idHex = null;
      this.label = Args.notBlank(label, "label");
    } else {
      this.id = id;
      this.idHex = Hex.encode(id);
      this.label = label;
    }
  }

  public long getHandle() {
    return handle;
  }

  public byte[] getId() {
    return id;
  }

  public boolean matchesId(byte[] id) {
    return Arrays.equals(id, this.id);
  }

  public boolean matchesLabel(String label) {
    return CompareUtil.equalsObject(label, this.label);
  }

  public String getIdHex() {
    return idHex;
  }

  public String getLabel() {
    return label;
  }

  @Override
  public String toString() {
    return String.format("(handle = %d, id = %s, label = %s)", handle, idHex, label);
  }

  @Override
  public int hashCode() {
    return (int) handle;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    else if (!(obj instanceof P11ObjectId)) return false;

    P11ObjectId other = (P11ObjectId) obj;
    return handle == other.handle && Arrays.equals(id, other.id) && CompareUtil.equalsObject(label, other.label);
  }

  @Override
  public int compareTo(P11ObjectId obj) {
    notNull(obj, "obj");
    if (this == obj) {
      return 0;
    }

    if (label == null) {
      return obj.label == null ? 0 : 1;
    } else {
      return obj.label == null ? -1 : label.compareTo(obj.label);
    }
  }

}
