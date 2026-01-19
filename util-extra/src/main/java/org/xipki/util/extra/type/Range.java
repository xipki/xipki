// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.type;

import org.xipki.util.codec.Args;

/**
 * Range with optional min and max values.
 *
 * @author Lijun Liao (xipki)
 *
 */

public class Range {

  private int min;

  private int max;

  public Range(int min, int max) {
    setRange(min, max);
  }

  public void setRange(int min, int max) {
    Args.min(max, "max", min);
    this.min = min;
    this.max = max;
  }

  public int getMin() {
    return min;
  }

  public int getMax() {
    return max;
  }

  @Override
  public String toString() {
    return "[" + min + "," + max + "]";
  }

}
