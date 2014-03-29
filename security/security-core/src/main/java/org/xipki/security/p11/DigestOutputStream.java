/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This work is part of XiPKI, owned by Lijun Liao (lijun.liao@gmail.com)
 *
 */

package org.xipki.security.p11;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.Digest;

public class DigestOutputStream
    extends OutputStream
{
    private Digest digest;

    public DigestOutputStream(Digest digest)
    {
        this.digest = digest;
    }

    public void reset()
    {
    	digest.reset();
    }
    
    @Override
    public void write(byte[] bytes, int off, int len)
        throws IOException
    {
    	digest.update(bytes, off, len);
    }

    @Override    
    public void write(byte[] bytes)
        throws IOException
    {
    	digest.update(bytes, 0, bytes.length);
    }

    @Override
    public void write(int b)
        throws IOException
    {
    	digest.update((byte)b);
    }
    
    public byte[] digest()
    {
    	byte[] result = new byte[digest.getDigestSize()];
    	digest.doFinal(result, 0);
    	reset();
    	return result;
    }

}
