// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security;

import java.security.NoSuchAlgorithmException;

/**
 * Sign Algorithm Mode.
 *
 * @author Lijun Liao (xipki)
 */
public enum SignAlgoMode {

  RSAPKCS1,
  RSAPSS;

  public static SignAlgoMode getInstance(String str)
      throws NoSuchAlgorithmException {
    for (SignAlgoMode v : SignAlgoMode.values()) {
      if (v.name().equalsIgnoreCase(str)) {
        return v;
      }
    }

    throw new NoSuchAlgorithmException(
        "Found no SignAlgoMode for '" + str + "'");
  }

}
