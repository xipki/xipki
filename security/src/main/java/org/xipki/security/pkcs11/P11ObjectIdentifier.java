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

public class P11ObjectIdentifier implements Comparable<P11ObjectIdentifier> {

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
  public P11ObjectIdentifier(byte[] id, String label) {
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

  public char[] getLabelChars() {
    return label == null ? null : label.toCharArray();
  }

  @Override
  public String toString() {
    return String.format("(id = %s, label = %s)", idHex, label);
  }

  @Override
  public int hashCode() {
    int hashCode = id == null ? 0 : Arrays.hashCode(id);
    if (label != null) {
      hashCode += 31 * label.hashCode();
    }
    return hashCode;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof P11ObjectIdentifier)) {
      return false;
    }

    P11ObjectIdentifier another = (P11ObjectIdentifier) obj;
    return Arrays.equals(id, another.id) && CompareUtil.equalsObject(label, another.label);
  }

  @Override
  public int compareTo(P11ObjectIdentifier obj) {
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
