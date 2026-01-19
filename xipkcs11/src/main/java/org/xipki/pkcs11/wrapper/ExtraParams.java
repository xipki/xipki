// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * Provides extra parameters, e.g. the order bit-size of an EC curve.
 *
 * @author Lijun Liao (xipki)
 */
public class ExtraParams {

  private int ecOrderBitSize;

  public int ecOrderBitSize() {
    return ecOrderBitSize;
  }

  public ExtraParams ecOrderBitSize(int ecOrderBitSize) {
    this.ecOrderBitSize = ecOrderBitSize;
    return this;
  }

}
