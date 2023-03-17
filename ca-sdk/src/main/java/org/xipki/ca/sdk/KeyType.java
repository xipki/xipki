// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class KeyType {

  private String keyType;

  private String[] ecCurves;

  public String getKeyType() {
    return keyType;
  }

  public void setKeyType(String keyType) {
    this.keyType = keyType;
  }

  public String[] getEcCurves() {
    return ecCurves;
  }

  public void setEcCurves(String[] ecCurves) {
    this.ecCurves = ecCurves;
  }
}
