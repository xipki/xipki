/*
 * Copyright (c) 2015 Lijun Liao
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

package org.xipki.scep4j.transaction;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.scep4j.util.ParamChecker;

/**
 * @author Lijun Liao
 */

public class TransactionId
{
    private static final SecureRandom random = new SecureRandom();

    private final String id;

    public TransactionId(
            final String id)
    {
        ParamChecker.assertNotBlank("id", id);
        this.id = id;
    }

    private TransactionId(
            final byte[] bytes)
    {
        ParamChecker.assertNotNull("bytes", bytes);
        if(bytes.length < 1)
        {
            throw new IllegalArgumentException("bytes could not be null");
        }
        this.id = Hex.toHexString(bytes);
    }

    public String getId()
    {
        return id;
    }

    public static TransactionId randomTransactionId()
    {
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        return new TransactionId(bytes);
    }

    public static TransactionId sha1TransactionId(
            final SubjectPublicKeyInfo spk)
    throws InvalidKeySpecException
    {
        ParamChecker.assertNotNull("spk", spk);
        byte[] encoded;
        try
        {
            encoded = spk.getEncoded();
        } catch (IOException e)
        {
            throw new InvalidKeySpecException("IO exception while ");
        }

        return sha1TransactionId(encoded);
    }

    public static TransactionId sha1TransactionId(
            final byte[] content)
    {
        ParamChecker.assertNotNull("content", content);
        SHA1Digest dgst = new SHA1Digest();
        dgst.update(content, 0, content.length);
        final int size = 20;
        byte[] digest = new byte[size];
        dgst.doFinal(digest, 0);
        return new TransactionId(digest);
    }

}
