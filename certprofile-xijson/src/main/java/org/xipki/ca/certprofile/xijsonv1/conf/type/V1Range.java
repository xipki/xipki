// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.type;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.misc.StringUtil;

/**
 * Range with optional min and max values.
 *
 * @author Lijun Liao (xipki)
 */

public class V1Range {

  private final Integer min;

  private final Integer max;

  public V1Range(Integer min, Integer max) {
    if (min == null && max == null) {
      throw new IllegalArgumentException("min and max may not be both null");
    }
    if (min != null && max != null && min > max) {
      throw new IllegalArgumentException(String.format(
          "min may not be greater than max: %d > %d", min, max));
    }

    this.min = min;
    this.max = max;
  }

  public Integer min() {
    return min;
  }

  public Integer max() {
    return max;
  }

  @Override
  public String toString() {
    return StringUtil.concatObjects("[", (min == null ? "" : min), ",",
        (max == null ? "" : max), "]");
  }

  public static V1Range parse(JsonMap json) throws CodecException {
    return new V1Range(json.getInt("min"), json.getInt("max"));
  }

}
