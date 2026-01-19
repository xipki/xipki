// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.util;

/**
 * @author Lijun Liao (xipki)
 */
public enum OperationType {
  SIGN("C_Sign"),
  DIGEST("C_Digest"),
  FIND_OBJECTS("C_FindObjects");

  private final String method;

  OperationType(String method) {
    this.method = method;
  }

  public String getMethod() {
    return method;
  }

}
