/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
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
