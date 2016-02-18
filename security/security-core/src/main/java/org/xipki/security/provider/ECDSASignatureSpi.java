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

package org.xipki.security.provider;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

/**
 * @author Lijun Liao
 */

class ECDSASignatureSpi extends SignatureSpi
{
    private Digest digest;

    private P11PrivateKey signingKey;

    ECDSASignatureSpi(Digest digest)
    {
        this.digest = digest;
    }

    protected void engineInitVerify(PublicKey publicKey)
    throws InvalidKeyException
    {
        throw new UnsupportedOperationException("engineInitVerify unsupported");
    }

    protected void engineInitSign(
        PrivateKey privateKey)
    throws InvalidKeyException
    {
        if(privateKey instanceof P11PrivateKey == false)
        {
            throw new InvalidKeyException("privateKey is not instanceof " + P11PrivateKey.class.getName());
        }

        String algo = privateKey.getAlgorithm();
        if(("EC".equals(algo) || "ECDSA".equals(algo)) == false)
        {
            throw new InvalidKeyException("privateKey is not a EC private key: " + algo);
        }

        digest.reset();
        this.signingKey = (P11PrivateKey) signingKey;
    }

/**
 * @author Lijun Liao
 */

    static public class SHA1
        extends ECDSASignatureSpi
    {
        public SHA1()
        {
            super(new SHA1Digest());
        }
    }

    static public class NONE
        extends ECDSASignatureSpi
    {
        public NONE()
        {
            super(new NullDigest());
        }
    }

    static public class SHA224
        extends ECDSASignatureSpi
    {
        public SHA224()
        {
            super(new SHA224Digest());
        }
    }

    static public class SHA256
        extends ECDSASignatureSpi
    {
        public SHA256()
        {
            super(new SHA256Digest());
        }
    }

    static public class SHA384
        extends ECDSASignatureSpi
    {
        public SHA384()
        {
            super(new SHA384Digest());
        }
    }

    static public class SHA512
        extends ECDSASignatureSpi
    {
        public SHA512()
        {
            super(new SHA512Digest());
        }
    }

    static public class RIPEMD160
        extends ECDSASignatureSpi
    {
        public RIPEMD160()
        {
            super(new RIPEMD160Digest());
        }
    }

    protected void engineUpdate(
        byte    b)
    throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len)
    throws SignatureException
    {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
    throws SignatureException
    {
        byte[]  hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        try
        {
            return signingKey.CKM_ECDSA(hash);
        }
        catch(SignatureException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with <a href = "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">
     */
    protected void engineSetParameter(
        String  param,
        Object  value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(
        String      param)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected boolean engineVerify(
        byte[]  sigBytes)
    throws SignatureException
    {
        throw new UnsupportedOperationException("engineVerify unsupported");
    }
}
