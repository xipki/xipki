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

package org.xipki.ca.server.impl;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntBinaryOperator;

import org.xipki.common.util.ParamUtil;

/**
 * An id consists of
 * <ol>
 *  <li>highest bit is set to 0 to assure positive long.
 *  <li>epoch in ms: 46 bits for 1312 years after the epoch</li>
 *  <li>offset: 10 bits
 *  <li>shard_id: 7 bits
 * </ol>
 *
 * Idea is borrowed from http://instagram-engineering.tumblr.com/post/10853187575/sharding-ids-at-instagram
 * @author Lijun Liao
 * @since 2.0.0
 *
 */

public class UniqueIdGenerator {

    private static class OffsetIncrement implements IntBinaryOperator {

        @Override
        public int applyAsInt(int left, int right) {
            return (left >= right) ? 0 : left + 1;
        }

    }

    // maximal 10 bits
    private static final int MAX_OFFSET = 0x3FF;

    private final long epoch; // in milliseconds

    private final int shardId; // 7 bits

    private final AtomicInteger offset = new AtomicInteger(0);

    private final IntBinaryOperator accumulatorFunction;

    public UniqueIdGenerator(long epoch, int shardId) {
        this.epoch = ParamUtil.requireMin("epoch", epoch, 0);
        this.shardId = ParamUtil.requireRange("shardId", shardId, 0, 127);
        this.accumulatorFunction = new OffsetIncrement();
    }

    public long nextId() {
        long now = System.currentTimeMillis();
        long ret = now - epoch;
        ret <<= 10;

        ret += offset.getAndAccumulate(MAX_OFFSET, accumulatorFunction);
        ret <<= 7;

        ret += shardId;
        return ret;
    }

}
