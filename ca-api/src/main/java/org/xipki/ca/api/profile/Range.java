/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.api.profile;

import org.xipki.util.StringUtil;

/**
 * Range with optional min and max values.
 *
 * @author Lijun Liao
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

  public boolean match(int val) {
    if (min != null && val < min) {
      return false;
    }
    if (max != null && val > max) {
      return false;
    }

    return true;
  }

  public void validate() {
    validate(min, max);
  }

  private static void validate(Integer min, Integer max) {
    if (min == null && max == null) {
      throw new IllegalArgumentException("min and max may not be both null");
    }
    if (min != null && max != null && min > max) {
      throw new IllegalArgumentException(String.format(
          "min may not be greater than max: %d > %d", min, max));
    }
  }

  @Override
  public String toString() {
    return StringUtil.concatObjects("[", (min == null ? "" : min), ",",
        (max == null ? "" : max), "]");
  }

}
