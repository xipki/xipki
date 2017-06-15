/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.server.impl;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntBinaryOperator;

import org.xipki.common.util.ParamUtil;

/**
 * Idea: http://instagram-engineering.tumblr.com/post/10853187575/sharding-ids-at-instagram
 * <br/>
 * id consists of
 * <ol>
 *  <li>highest bit is set to 0 to assure positive long.
 *  <li>epoch in ms: 46 bits for 1312 years after the epoch</li>
 *  <li>offset: 10 bits
 *  <li>shard_id: 7 bits
 * </ol>
 *
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

    public UniqueIdGenerator(final long epoch, final int shardId) {
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
