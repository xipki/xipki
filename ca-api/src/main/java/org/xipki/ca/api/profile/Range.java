// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.xipki.util.StringUtil;

/**
 * Range with optional min and max values.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class Range {

  private Integer min;

  private Integer max;

  public Range() {
  }

  public Range(Integer min, Integer max) {
    setMin(min);
    setMax(max);
    validate();
  }

  public Integer getMin() {
    return min;
  }

  public void setMin(Integer min) {
    this.min = min;
  }

  public Integer getMax() {
    return max;
  }

  public void setMax(Integer max) {
    this.max = max;
  }

  public void setRange(Integer min, Integer max) {
    validate(min, max);
    setMin(min);
    setMax(max);
  }

  public void validate() {
    validate(min, max);
  }

  private static void validate(Integer min, Integer max) {
    if (min == null && max == null) {
      throw new IllegalArgumentException("min and max may not be both null");
    }
    if (min != null && max != null && min > max) {
      throw new IllegalArgumentException(String.format("min may not be greater than max: %d > %d", min, max));
    }
  }

  @Override
  public String toString() {
    return StringUtil.concatObjects("[", (min == null ? "" : min), ",", (max == null ? "" : max), "]");
  }

}
