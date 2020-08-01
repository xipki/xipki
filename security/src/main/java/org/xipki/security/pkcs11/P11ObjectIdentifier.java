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

import static org.xipki.util.Args.notNull;

import java.math.BigInteger;
import java.util.Arrays;

import org.xipki.util.Hex;

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
   *          Identifier. Must not be {@code null}.
   * @param label
   *          Label. Must not be {@code null}.
   */
  public P11ObjectIdentifier(byte[] id, String label) {
    this.id = notNull(id, "id");
    this.label = notNull(label, "label");
    this.idHex = Hex.encode(id);
  }

  public byte[] getId() {
    return id;
  }

  public boolean matchesId(byte[] id) {
    return Arrays.equals(id, this.id);
  }

  public String getIdHex() {
    return idHex;
  }

  public String getLabel() {
    return label;
  }

  public char[] getLabelChars() {
    return label.toCharArray();
  }

  @Override
  public String toString() {
    return String.format("(id = %s, label = %s)", idHex, label);
  }

  @Override
  public int hashCode() {
    int hashCode = new BigInteger(1, id).hashCode();
    hashCode += 31 * label.hashCode();
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
    return Arrays.equals(id, another.id) && label.equals(another.label);
  }

  @Override
  public int compareTo(P11ObjectIdentifier obj) {
    notNull(obj, "obj");
    if (this == obj) {
      return 0;
    }

    return label.compareTo(obj.label);
  }

}
