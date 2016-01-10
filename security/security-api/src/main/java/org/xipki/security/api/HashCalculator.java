/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.security.api;

import java.util.concurrent.BlockingDeque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.common.util.Base64;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 */

public class HashCalculator {

    private final static int parallelism = 50;

    private final static ConcurrentHashMap<HashAlgoType, BlockingDeque<Digest>> mdsMap =
            new ConcurrentHashMap<>();

    static {
        mdsMap.put(HashAlgoType.SHA1, getMessageDigests(HashAlgoType.SHA1));
        mdsMap.put(HashAlgoType.SHA224, getMessageDigests(HashAlgoType.SHA224));
        mdsMap.put(HashAlgoType.SHA256, getMessageDigests(HashAlgoType.SHA256));
        mdsMap.put(HashAlgoType.SHA384, getMessageDigests(HashAlgoType.SHA384));
        mdsMap.put(HashAlgoType.SHA512, getMessageDigests(HashAlgoType.SHA512));
    }

    private HashCalculator() {
    }

    private static BlockingDeque<Digest> getMessageDigests(
            final HashAlgoType hashAlgo) {
        BlockingDeque<Digest> mds = new LinkedBlockingDeque<>();
        for (int i = 0; i < parallelism; i++) {
            Digest md;
            switch (hashAlgo) {
                case SHA1:
                    md = new SHA1Digest();
                    break;
                case SHA224:
                    md = new SHA224Digest();
                    break;
                case SHA256:
                    md = new SHA256Digest();
                    break;
                case SHA384:
                    md = new SHA384Digest();
                    break;
                case SHA512:
                    md = new SHA512Digest();
                    break;
                default:
                    throw new RuntimeException(
                            "should not reach here, unknown HashAlgoType " + hashAlgo);
            }
            mds.addLast(md);
        }
        return mds;
    }

    public static String base64Sha1(
            final byte[] data) {
        return base64Hash(HashAlgoType.SHA1, data);
    }

    public static String hexSha1(
            final byte[] data) {
        return hexHash(HashAlgoType.SHA1, data);
    }

    public static byte[] sha1(
            final byte[] data) {
        return hash(HashAlgoType.SHA1, data);
    }

    public static String base64Sha256(
            final byte[] data) {
        return base64Hash(HashAlgoType.SHA256, data);
    }

    public static String hexSha256(
            final byte[] data) {
        return hexHash(HashAlgoType.SHA256, data);
    }

    public static byte[] sha256(
            final HashAlgoType hashAlgoType,
            final byte[] data) {
        return hash(HashAlgoType.SHA256, data);
    }

    public static String hexHash(
            final HashAlgoType hashAlgoType,
            final byte[] data) {
        byte[] bytes = hash(hashAlgoType, data);
        return (bytes == null)
                ? null
                : Hex.toHexString(bytes).toUpperCase();
    }

    public static String base64Hash(
            final HashAlgoType hashAlgoType,
            final byte[] data) {
        byte[] bytes = hash(hashAlgoType, data);
        return (bytes == null)
                ? null
                : Base64.encodeToString(bytes, Base64.NO_WRAP);
    }

    public static byte[] hash(
            final HashAlgoType hashAlgoType,
            final byte[] data) {
        ParamUtil.assertNotNull("hashAlgoType", hashAlgoType);
        ParamUtil.assertNotNull("data", data);
        if (!mdsMap.containsKey(hashAlgoType)) {
            throw new IllegalArgumentException("unknown hash algo " + hashAlgoType);
        }

        BlockingDeque<Digest> mds = mdsMap.get(hashAlgoType);

        Digest md = null;
        for (int i = 0; i < 3; i++) {
            try {
                md = mds.poll(10, TimeUnit.SECONDS);
                break;
            } catch (InterruptedException e) {
            }
        }

        if (md == null) {
            throw new RuntimeOperatorException("could not get idle MessageDigest");
        }

        try {
            md.reset();
            md.update(data, 0, data.length);
            byte[] b = new byte[md.getDigestSize()];
            md.doFinal(b, 0);
            return b;
        } finally {
            mds.addLast(md);
        }
    }

}
