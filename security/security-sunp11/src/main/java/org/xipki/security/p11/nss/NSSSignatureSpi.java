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

package org.xipki.security.p11.nss;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.xipki.security.common.HashAlgoType;

/**
 * @author Lijun Liao
 */

public class NSSSignatureSpi extends SignatureSpi
{
    private final Signature service;

    private final ASN1ObjectIdentifier hashAlgOid;
    private final MessageDigest md;
    private final Cipher cipher;

    private static final String MSG_UNSUPPORTED_ALGO = "Unsupported signature algorithm (digestAlgo: %s, encryptionAlgo: %s)";

        private NSSSignatureSpi(String algorithm)
        {
            this.service = getSignatureService(algorithm);
            this.md = null;
            this.cipher = null;
            this.hashAlgOid = null;
        }

    private NSSSignatureSpi(String digestAlgorithmName, String encrAlgorithmName)
    {
        String HASHALGO = digestAlgorithmName.toUpperCase();
        String ENCALGO = encrAlgorithmName.toUpperCase();
        if(RSA.equalsIgnoreCase(ENCALGO) || ECDSA.equals(ENCALGO))
        {
            if (! (SHA1.equals(HASHALGO) || SHA224.equals(HASHALGO) || SHA256.equals(HASHALGO) ||
                 SHA384.equals(HASHALGO) || SHA512.equals(HASHALGO)))
            {
                throw new ProviderException(String.format(MSG_UNSUPPORTED_ALGO, HASHALGO, ENCALGO));
            }
        }
        else
        {
            throw new ProviderException(String.format(MSG_UNSUPPORTED_ALGO, HASHALGO, encrAlgorithmName));
        }

        if(SHA224.equals(HASHALGO))
        {
            if(RSA.equals(ENCALGO))
            {
                this.service = null;
                this.cipher = getCipherService("RSA/ECB/NoPadding");
            }
            else // ECDSA
            {
                this.service = getSignatureService("NONEwithECDSA");
                this.cipher = null;
            }
            this.md = getMessageDigestService(HASHALGO);

            hashAlgOid = new ASN1ObjectIdentifier(HashAlgoType.SHA224.getOid());
        }
        else
        {
            this.service = getSignatureService(digestAlgorithmName + "with" + encrAlgorithmName);
            this.cipher = null;
            this.md = null;
            this.hashAlgOid = null;
        }
    }

    private static Signature getSignatureService(String algorithm)
    {
        Signature service = null;
        if(XipkiNSSProvider.nssProvider != null)
        {
            try
            {
                service = Signature.getInstance(algorithm, XipkiNSSProvider.nssProvider);
            } catch (NoSuchAlgorithmException e)
            {
                try
                {
                    service = Signature.getInstance(algorithm, "SunEC");
                } catch (NoSuchAlgorithmException e2)
                {
                    throw new ProviderException("Signature " + algorithm + "not supported");
                } catch (NoSuchProviderException e2)
                {
                    throw new ProviderException("Signature " + algorithm + "not supported");
                }
            }
        }

        if(service == null)
        {
             final String errorMsg = "Unsupported algorithm " + algorithm;
            throw new ProviderException(errorMsg);
        }

        return service;
    }

    private static Cipher getCipherService(String algorithm)
    {
        Cipher service = null;
        if(XipkiNSSProvider.nssProvider != null)
        {
            try
            {
                service = Cipher.getInstance(algorithm, XipkiNSSProvider.nssProvider);
            } catch (NoSuchAlgorithmException e)
            {
                throw new ProviderException("Cipher " + algorithm + " not supported");
            } catch (NoSuchPaddingException e)
            {
                throw new ProviderException("Cipher " + algorithm + " not supported");
            }
        }
        if(service == null)
        {
            final String errorMsg = "Unsupported algorithm " + algorithm;
            throw new ProviderException(errorMsg);
        }

        return service;
    }

    private static MessageDigest getMessageDigestService(String algorithm)
    {
        MessageDigest service = null;
        if(XipkiNSSProvider.nssProvider != null)
        {
            try
            {
                service = MessageDigest.getInstance(algorithm, XipkiNSSProvider.nssProvider);
            } catch (NoSuchAlgorithmException e)
            {
            }
        }

        if(service == null)
        {
            final String errorMsg = "Cannot find any provider for algorithm " + algorithm;
            try
            {
                service = MessageDigest.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e)
            {
                throw new ProviderException(errorMsg);
            }
        }

        return service;
    }

    @Override
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(String param)
    throws InvalidParameterException
    {
        if(service != null)
        {
            return service.getParameter(param);
        }
        else
        {
            throw new InvalidParameterException("parametrizing not supported");
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey)
    throws InvalidKeyException
    {
        if(service != null)
        {
            service.initSign(privateKey);
        }
        if(cipher != null)
        {
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        }
        if(md != null)
        {
            md.reset();
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
    throws InvalidKeyException
    {
        if(service != null)
        {
            service.initSign(privateKey, random);
        }
        if(cipher != null)
        {
            cipher.init(Cipher.ENCRYPT_MODE, privateKey, random);
        }
        if(md != null)
        {
            md.reset();
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey)
    throws InvalidKeyException
    {
        if(service != null)
        {
            service.initVerify(publicKey);
        }
        if(cipher != null)
        {
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
        }

        if(md != null)
        {
            md.reset();
        }
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
    throws InvalidAlgorithmParameterException
    {
        if(service != null)
        {
            service.setParameter(params);
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unsupported method setParameter");
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value)
    throws InvalidParameterException
    {
        if(service != null)
        {
            service.setParameter(param, value);
        }
        else
        {
            throw new InvalidParameterException("unsupported method setParameter");
        }
    }

    @Override
    protected byte[] engineSign()
    throws SignatureException
    {
        if(md != null && service != null)
        {
            byte[] digest = md.digest();
            service.update(digest);
            return service.sign();
        }
        else if(service != null)
        {
            return service.sign();
        }
        else
        {
            return encryptHash(md.digest());
        }
    }

    @Override
    protected int engineSign(byte[] outbuf, int offset, int len)
    throws SignatureException
    {
        if(md != null && service != null)
        {
            byte[] digest = md.digest();
            service.update(digest);
            return service.sign(outbuf, offset, len);
        }
        else if(service != null)
        {
            return service.sign(outbuf, offset, len);
        }
        else
        {
            int sigLen = cipher.getOutputSize(1);
            if(sigLen > len)
            {
                throw new SignatureException("len is less than signature output size");
            }
            if(outbuf.length - offset < sigLen)
            {
                throw new SignatureException("not enough buffer to save signature");
            }
            byte[] signature = encryptHash(md.digest());
            System.arraycopy(signature, 0, outbuf, offset, signature.length);
            return signature.length;
        }
    }

    private byte[] encryptHash(byte[] hash)
    throws SignatureException
    {
        int blockSize =    cipher.getOutputSize(1) - 1;

        byte[] tbsHash;

        try
        {
            AlgorithmIdentifier hashAlgId = new AlgorithmIdentifier(hashAlgOid, DERNull.INSTANCE);
            tbsHash = pkcs1padding(derEncode(hashAlgId, hash), blockSize);
        } catch (IOException e)
        {
            throw new SignatureException(e);
        }

        try
        {
            return cipher.doFinal(tbsHash);
        } catch (IllegalBlockSizeException e)
        {
            throw new SignatureException(e);
        } catch (BadPaddingException e)
        {
            throw new SignatureException(e);
        }
    }

    @Override
    protected void engineUpdate(byte b)
    throws SignatureException
    {
        if(md != null)
        {
            md.update(b);
        }
        else
        {
            service.update(b);
        }
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len)
    throws SignatureException
    {
        if(md != null)
        {
            md.update(b, off, len);
        }
        else
        {
            service.update(b, off, len);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes)
    throws SignatureException
    {
        if(md != null && service != null)
        {
            byte[] digest = md.digest();
            service.update(digest);
            return service.verify(sigBytes);
        }
        else if(service != null)
        {
            return service.verify(sigBytes);
        }
        else
        {
            byte[] encodedHash;
            try
            {
                encodedHash = decodePkcs11Block(cipher.doFinal(sigBytes), cipher.getOutputSize(1)-1);
            } catch (Exception e)
            {
                throw new SignatureException(e);
            }

            byte[] hash = md.digest();

            ASN1InputStream ain = null;
            try
            {
                ain = new ASN1InputStream(encodedHash);
                ASN1Encodable obj = ain.readObject();
                if(obj instanceof ASN1Sequence)
                {
                    DigestInfo di = new DigestInfo((ASN1Sequence) obj);
                    if(di.getAlgorithmId().getAlgorithm().equals(hashAlgOid))
                    {
                        ASN1Encodable params = di.getAlgorithmId().getParameters();
                        if(params == null || params.equals(DERNull.INSTANCE))
                        {
                            return Arrays.equals(hash, di.getDigest());
                        }
                    }
                }
            } catch (IOException e)
            {
                throw new SignatureException(e);
            } finally
            {
                if(ain != null)
                {
                    try
                    {
                        ain.close();
                    }catch(IOException e)
                    {
                    }
                }
            }

            return false;
        }
    }

    private static byte[] pkcs1padding(byte[] in, int blockSize)
    {
        int inLen = in.length;
        if (inLen > blockSize)
        {
            throw new IllegalArgumentException("input data too large");
        }

        byte[]    block = new byte[blockSize];

        block[0] = 0x01;                                                // type code 1
        for (int i = 1; i != block.length - inLen - 1; i++)
        {
            block[i] = (byte)0xFF;
        }

        block[block.length - inLen - 1] = 0x00;             // mark the end of the padding
        System.arraycopy(in, 0, block, block.length - inLen, inLen);
        return block;
    }

    private static byte[] decodePkcs11Block(
        byte[]    block,
        int minLen)
    throws InvalidCipherTextException
    {
        int offset = 0;
        while(block[offset] == 0)
        {
            offset++;
        }

        if (block.length - offset < minLen)
        {
            throw new InvalidCipherTextException("block truncated");
        }

        byte type = block[offset];

        if (type != 1)
        {
            throw new InvalidCipherTextException("unknown block type");
        }

        // find and extract the message block.
        int start;
        for (start = offset+1; start != block.length; start++)
        {
            byte pad = block[start];
            if (pad == 0)
            {
                break;
            }
            if (pad != (byte)0xff)
            {
                throw new InvalidCipherTextException("block padding incorrect");
            }
        }

        start++;                     // data should start at the next byte

        final int HEADER_LENGTH = 10;

        if (start > block.length || start < HEADER_LENGTH)
        {
            throw new InvalidCipherTextException("no data in block");
        }

        byte[]    result = new byte[block.length - start];
        System.arraycopy(block, start, result, 0, result.length);

        return result;
    }

    private static byte[] derEncode(
        AlgorithmIdentifier algId,
        byte[]    hash)
    throws IOException
    {
        if (algId == null)
        {
            // For raw RSA, the DigestInfo must be prepared externally
            return hash;
        }

        DigestInfo dInfo = new DigestInfo(algId, hash);

        return dInfo.getEncoded("DER");
    }

    public static final String SHA1 = "SHA1";
    public static final String SHA224 = "SHA224";
    public static final String SHA256 = "SHA256";
    public static final String SHA384 = "SHA384";
    public static final String SHA512 = "SHA512";

    public static final String RSA = "RSA";
    public static final String ECDSA = "ECDSA";

    public static class SHA1withRSA extends NSSSignatureSpi
    {
        public SHA1withRSA()
        {
            super(SHA1, RSA);
        }
    }

    public static class SHA224withRSA extends NSSSignatureSpi
    {
        public SHA224withRSA()
        {
            super(SHA224, RSA);
        }
    }

    public static class SHA256withRSA extends NSSSignatureSpi
    {
        public SHA256withRSA()
        {
            super(SHA256, RSA);
        }
    }

    public static class SHA384withRSA extends NSSSignatureSpi
    {
        public SHA384withRSA()
        {
            super(SHA384, RSA);
        }
    }

    public static class SHA512withRSA extends NSSSignatureSpi
    {
        public SHA512withRSA()
        {
            super(SHA512, RSA);
        }
    }

    public static class SHA1withECDSA extends NSSSignatureSpi
    {
        public SHA1withECDSA()
        {
            super(SHA1, ECDSA);
        }
    }

    public static class SHA256withECDSA extends NSSSignatureSpi
    {
        public SHA256withECDSA()
        {
            super(SHA256, ECDSA);
        }
    }

    public static class SHA384withECDSA extends NSSSignatureSpi
    {
        public SHA384withECDSA()
        {
            super(SHA384, ECDSA);
        }
    }

    public static class SHA512withECDSA extends NSSSignatureSpi
    {
        public SHA512withECDSA()
        {
            super(SHA512, ECDSA);
        }
    }

    public static class RawECDSA extends NSSSignatureSpi
    {
        public RawECDSA()
        {
            super("NONEwith" + ECDSA);
        }
    }

    public static class SHA224withECDSA extends NSSSignatureSpi
    {
        public SHA224withECDSA()
        {
            super(SHA224, ECDSA);
        }
    }

}
