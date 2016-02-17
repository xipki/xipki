/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
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

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

/**
 * @author Lijun Liao
 */

class RSADigestSignatureSpi
    extends SignatureSpi
{
    private Digest digest;
    private AlgorithmIdentifier algId;
    private P11PrivateKey signingKey;

    // care - this constructor is actually used by outside organisations
    protected RSADigestSignatureSpi(
        Digest digest)
    {
        this.digest = digest;
        this.algId = null;
    }

    // care - this constructor is actually used by outside organisations
    protected RSADigestSignatureSpi(
        ASN1ObjectIdentifier objId,
        Digest digest)
    {
        this.digest = digest;
        this.algId = new AlgorithmIdentifier(objId, DERNull.INSTANCE);
    }

    protected void engineInitVerify(
        PublicKey publicKey)
    throws InvalidKeyException
    {
        throw new UnsupportedOperationException("engineVerify unsupported");
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
        if("RSA".equals(algo) == false)
        {
            throw new InvalidKeyException("privateKey is not an RSA private key: " + algo);
        }

        digest.reset();
        this.signingKey = (P11PrivateKey) privateKey;
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
            byte[]  bytes = derEncode(hash);

            return signingKey.CKM_RSA_PKCS(bytes);
        }
        catch (ArrayIndexOutOfBoundsException e)
        {
            throw new SignatureException("key too small for signature type");
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(
        byte[]  sigBytes)
    throws SignatureException
    {
        throw new UnsupportedOperationException("engineVerify unsupported");
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
        String param,
        Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(
        String param)
    {
        return null;
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    private byte[] derEncode(
        byte[]  hash)
    throws IOException
    {
        if (algId == null)
        {
            // For raw RSA, the DigestInfo must be prepared externally
            return hash;
        }

        DigestInfo dInfo = new DigestInfo(algId, hash);

        return dInfo.getEncoded(ASN1Encoding.DER);
    }

/**
 * @author Lijun Liao
 */

    static public class SHA1
        extends RSADigestSignatureSpi
    {
        public SHA1()
        {
            super(OIWObjectIdentifiers.idSHA1, new SHA1Digest());
        }
    }

    static public class SHA224
        extends RSADigestSignatureSpi
    {
        public SHA224()
        {
            super(NISTObjectIdentifiers.id_sha224, new SHA224Digest());
        }
    }

    static public class SHA256
        extends RSADigestSignatureSpi
    {
        public SHA256()
        {
            super(NISTObjectIdentifiers.id_sha256, new SHA256Digest());
        }
    }

    static public class SHA384
        extends RSADigestSignatureSpi
    {
        public SHA384()
        {
            super(NISTObjectIdentifiers.id_sha384, new SHA384Digest());
        }
    }

    static public class SHA512
        extends RSADigestSignatureSpi
    {
        public SHA512()
        {
            super(NISTObjectIdentifiers.id_sha512, new SHA512Digest());
        }
    }

    static public class RIPEMD160
        extends RSADigestSignatureSpi
    {
        public RIPEMD160()
        {
            super(TeleTrusTObjectIdentifiers.ripemd160, new RIPEMD160Digest());
        }
    }

    static public class RIPEMD256
        extends RSADigestSignatureSpi
    {
        public RIPEMD256()
        {
            super(TeleTrusTObjectIdentifiers.ripemd256, new RIPEMD256Digest());
        }
    }

    static public class noneRSA
        extends RSADigestSignatureSpi
    {
        public noneRSA()
        {
            super(new NullDigest());
        }
    }
}
