/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

import org.xipki.commons.common.util.ParamUtil;

/**
 * Idea: http://instagram-engineering.tumblr.com/post/10853187575/sharding-ids-at-instagram
 * <br/>
 * id consists of
 * <ol>
 *  <li>highest bit is set to 0 to assure positive long.
 *  <li>epoch in ms: 46 bits for 1312 years after the epoch</li>
 *  <li>offset: 9 bits
 *  <li>shard_id: 8 bits
 * </ol>
 *
 * @author Lijun Liao
 * @since 2.0.0
 *
 */

public class UniqueIdGenerator {

    // maximal 9 bits
    private static final int MAX_OFFSET = 0x1FF;

    private final long epoch; // in milliseconds

    private final int shardId; // 8 bits

    private int offset = 0;

    public UniqueIdGenerator(final long epoch, final int shardId) {
        this.epoch = ParamUtil.requireMin("epoch", epoch, 0);
        this.shardId = ParamUtil.requireRange("shardId", shardId, 0, 255);
    }

    public long nextId() {
        long now = System.currentTimeMillis();
        synchronized (this) {
            long ret = now - epoch;
            ret <<= 8;

            ret += (offset++);
            ret <<= 9;

            if (offset > MAX_OFFSET) {
                offset = 0;
            }

            ret += shardId;

            return ret;
        }
    }

}
