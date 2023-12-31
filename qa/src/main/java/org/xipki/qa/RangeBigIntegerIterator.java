// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa;

import org.xipki.util.Args;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;

/**
 * Iterator which iterates the {@link BigInteger} as specified by a list of
 * {@link BigIntegerRange}s.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public class RangeBigIntegerIterator implements Iterator<BigInteger> {

  private final List<BigIntegerRange> ranges;

  private final int sizeRanges;

  private final boolean loop;

  private int currentIndex;

  private BigInteger currentNumber;

  public RangeBigIntegerIterator(List<BigIntegerRange> ranges, boolean loop) {
    this.ranges = Args.notEmpty(ranges, "ranges");
    this.sizeRanges = ranges.size();
    this.loop = loop;
    this.currentIndex = 0;
    this.currentNumber = ranges.get(0).getFrom();
  }

  @Override
  public synchronized boolean hasNext() {
    return currentNumber != null;
  }

  @Override
  public synchronized BigInteger next() {
    if (currentNumber == null) {
      return null;
    }

    BigInteger ret = currentNumber;

    BigInteger nextNumber = currentNumber.add(BigInteger.ONE);
    BigIntegerRange range = ranges.get(currentIndex);
    if (range.isInRange(nextNumber)) {
      currentNumber = nextNumber;
    } else {
      currentIndex++;
      if (loop && currentIndex >= sizeRanges) {
        currentIndex = 0;
      }

      currentNumber = (currentIndex < sizeRanges) ? ranges.get(currentIndex).getFrom() : null;
    }

    return ret;
  } // method next

}
