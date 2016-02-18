/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
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

package org.xipki.security.common;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.util.encoders.Hex;

/**
 * @author Lijun Liao
 */

public class HashCalculator
{
    private final static int parallelism = 50;
    private final static ConcurrentHashMap<HashAlgoType, BlockingDeque<MessageDigest>> mdsMap =
            new ConcurrentHashMap<>();

    static
    {
        mdsMap.put(HashAlgoType.SHA1, getMessageDigests("SHA-1"));
        mdsMap.put(HashAlgoType.SHA224, getMessageDigests("SHA-224"));
        mdsMap.put(HashAlgoType.SHA256, getMessageDigests("SHA-256"));
        mdsMap.put(HashAlgoType.SHA384, getMessageDigests("SHA-384"));
        mdsMap.put(HashAlgoType.SHA512, getMessageDigests("SHA-512"));
    }

    private static BlockingDeque<MessageDigest> getMessageDigests(String hashAlgo)
    {
        BlockingDeque<MessageDigest> mds = new LinkedBlockingDeque<>();
        for(int i = 0; i < parallelism; i++)
        {
            MessageDigest md;
            try
            {
                md = MessageDigest.getInstance(hashAlgo);
            } catch (NoSuchAlgorithmException e)
            {
                throw new RuntimeException("No such hash algorithm " + hashAlgo);
            }
            mds.addLast(md);
        }
        return mds;
    }

    public static String hexHash(HashAlgoType hashAlgoType, byte[] data)
    {
        byte[] bytes = hash(hashAlgoType, data);
        return bytes == null ? null : Hex.toHexString(bytes).toUpperCase();
    }

    public static byte[] hash(HashAlgoType hashAlgoType, byte[] data)
    {
        ParamChecker.assertNotNull("hashAlgoType", hashAlgoType);
        ParamChecker.assertNotNull("data", data);
        if(mdsMap.containsKey(hashAlgoType) == false)
        {
            throw new IllegalArgumentException("Unknown hash algo " + hashAlgoType);
        }

        BlockingDeque<MessageDigest> mds = mdsMap.get(hashAlgoType);

        MessageDigest md = null;
        for(int i = 0; i < 3; i++)
        {
            try
            {
                md = mds.poll(10, TimeUnit.SECONDS);
                break;
            } catch (InterruptedException e)
            {
            }
        }

        if(md == null)
        {
            throw new RuntimeOperatorException("Could not get idle MessageDigest");
        }

        try
        {
            md.reset();
            return md.digest(data);
        }finally
        {
            mds.addLast(md);
        }
    }
}
