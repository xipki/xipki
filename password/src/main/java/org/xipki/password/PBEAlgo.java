// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

/**
 * Password based encryption algorithm enum.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public enum PBEAlgo {

  PBEWithHmacSHA256AndAES_256(1, "PBEWithHmacSHA256AndAES_256");

  private final int code;

  private final String algoName;

  PBEAlgo(int code, String algoName) {
    this.code = code;
    this.algoName = algoName;
  }

  public int code() {
    return code;
  }

  public String algoName() {
    return algoName;
  }

  public static PBEAlgo forCode(int code) {
    for (PBEAlgo value : values()) {
      if (value.code == code) {
        return value;
      }
    }

    return null;
  }

}

