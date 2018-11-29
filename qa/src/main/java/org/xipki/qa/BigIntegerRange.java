/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.qa;

import java.math.BigInteger;

/**
 * TODO.
 * @author Lijun Liao
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
