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

package org.xipki.common.util;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class RangeBigIntegerIterator implements Iterator<BigInteger> {

    private final List<BigIntegerRange> ranges;

    private final int sizeRanges;

    private final boolean loop;

    private int currentIndex;

    private BigInteger currentNumber;

    public RangeBigIntegerIterator(List<BigIntegerRange> ranges, boolean loop) {
        this.ranges = ParamUtil.requireNonEmpty("ranges", ranges);
        this.sizeRanges = ranges.size();
        this.loop = loop;
        this.currentIndex = 0;
        this.currentNumber = ranges.get(0).from();
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

            currentNumber = (currentIndex < sizeRanges) ? ranges.get(currentIndex).from() : null;
        }

        return ret;
    }

}
