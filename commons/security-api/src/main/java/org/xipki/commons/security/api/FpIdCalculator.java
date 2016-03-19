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

package org.xipki.commons.security.api;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class FpIdCalculator {

    private static final int PARALLELISM = 50;

    private static final BlockingDeque<Digest> MDS = getMD5MessageDigests();

    private FpIdCalculator() {
    }

    private static BlockingDeque<Digest> getMD5MessageDigests() {
        BlockingDeque<Digest> mds = new LinkedBlockingDeque<>();
        for (int i = 0; i < PARALLELISM; i++) {
            Digest md = new SHA1Digest();
            mds.addLast(md);
        }
        return mds;
    }

    /**
     * Hash the data.getBytes("UTF-8") and returns the first 8 bytes of the hash value.
     * @return long represented of the first 8 bytes
     */
    public static long hash(
            final String data) {
        ParamUtil.requireNonNull("data", data);
        byte[] encoded;
        try {
            encoded = data.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
            encoded = data.getBytes();
        }
        return hash(encoded);
    }

    /**
     * Hash the data and returns the first 8 bytes of the hash value.
     * @return long represented of the first 8 bytes
     */
    public static long hash(
            final byte[] data) {
        ParamUtil.requireNonNull("data", data);

        Digest md = null;
        for (int i = 0; i < 3; i++) {
            try {
                md = MDS.poll(10, TimeUnit.SECONDS);
                break;
            } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
            }
        }

        if (md == null) {
            throw new RuntimeOperatorException("could not get idle MessageDigest");
        }

        try {
            md.reset();
            md.update(data, 0, data.length);
            byte[] bytes = new byte[md.getDigestSize()];
            md.doFinal(bytes, 0);

            return bytesToLong(bytes);
        } finally {
            MDS.addLast(md);
        }
    }

    private static long bytesToLong(
            final byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.put(bytes, 0, 8);
        buffer.flip(); //need flip
        return buffer.getLong();
    }

}
