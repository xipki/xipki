/*
 * Copyright (c) 2014 xipki.org
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
