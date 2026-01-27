// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa;

import java.math.BigInteger;

/**
 * Range with [from, to].
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public class BigIntegerRange {
  private final BigInteger from;
  private final BigInteger to;
  private final BigInteger diff;

  public BigIntegerRange(BigInteger from, BigInteger to) {
    if (from.compareTo(to) > 0) {
      throw new IllegalArgumentException(
          "from (" + from + ") may not be larger than to (" + to + ")");
    }
    this.from = from;
    this.to = to;
    this.diff = to.subtract(from);
  }

  public BigInteger getFrom() {
    return from;
  }

  public BigInteger getTo() {
    return to;
  }

  public BigInteger getDiff() {
    return diff;
  }

  public boolean isInRange(BigInteger num) {
    return num.compareTo(from) >= 0 && num.compareTo(to) <= 0;
  }

}
