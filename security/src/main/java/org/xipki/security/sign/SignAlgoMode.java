// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.sign;

import java.security.NoSuchAlgorithmException;

/**
 * Sign Algo Mode enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum SignAlgoMode {

  RSAPKCS1,
  RSAPSS;

  public static SignAlgoMode getInstance(String str) throws NoSuchAlgorithmException {
    for (SignAlgoMode v : SignAlgoMode.values()) {
      if (v.name().equalsIgnoreCase(str)) {
        return v;
      }
    }

    throw new NoSuchAlgorithmException("Found no SignAlgoMode for '" + str + "'");
  }

}
