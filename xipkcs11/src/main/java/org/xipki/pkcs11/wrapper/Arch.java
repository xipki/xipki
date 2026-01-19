// Copyright (c) 2022-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * Arch information of the underlying PKCS#11 library.
 * @author Lijun Liao (xipki)
 */
public class Arch {

  private final boolean littleEndian;

  private final int longSize;

  public Arch(boolean littleEndian, int longSize) {
    this.littleEndian = littleEndian;
    this.longSize = longSize;
  }

  public boolean littleEndian() {
    return littleEndian;
  }

  public int longSize() {
    return longSize;
  }

  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof Arch)) {
      return false;
    }

    Arch b = (Arch) obj;
    return littleEndian == b.littleEndian && longSize == b.longSize;
  }

}
