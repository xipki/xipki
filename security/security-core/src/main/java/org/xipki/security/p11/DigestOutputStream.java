/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.Digest;

/**
 * @author Lijun Liao
 */

public class DigestOutputStream extends OutputStream
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
