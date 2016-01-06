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

package org.xipki.security.p11.sun.nss;

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
import org.xipki.security.api.HashAlgoType;

/**
 * @author Lijun Liao
 */

public class NSSSignatureSpi extends SignatureSpi {
    private final Signature service;

    private final ASN1ObjectIdentifier hashAlgOid;
    private final MessageDigest md;
    private final Cipher cipher;

    private static final String MSG_UNSUPPORTED_ALGO =
            "unsupported signature algorithm (digestAlgo: %s, encryptionAlgo: %s)";

    private NSSSignatureSpi(
            final String algorithm) {
        this.service = getSignatureService(algorithm);
        this.md = null;
        this.cipher = null;
        this.hashAlgOid = null;
    }

    private NSSSignatureSpi(
            final String digestAlgorithmName,
            final String encrAlgorithmName) {
        String HASHALGO = digestAlgorithmName.toUpperCase();
        String ENCALGO = encrAlgorithmName.toUpperCase();
        if (RSA.equalsIgnoreCase(ENCALGO) || ECDSA.equals(ENCALGO)) {
            if (!(SHA1.equals(HASHALGO) || SHA224.equals(HASHALGO) || SHA256.equals(HASHALGO)
                    || SHA384.equals(HASHALGO) || SHA512.equals(HASHALGO))) {
                throw new ProviderException(String.format(MSG_UNSUPPORTED_ALGO, HASHALGO, ENCALGO));
            }
        } else {
            throw new ProviderException(String.format(MSG_UNSUPPORTED_ALGO,
                    HASHALGO, encrAlgorithmName));
        }

        if (SHA224.equals(HASHALGO)) {
            if (RSA.equals(ENCALGO)) {
                this.service = null;
                this.cipher = getCipherService("RSA/ECB/NoPadding");
            } else { // ECDSA
                this.service = getSignatureService("NONEwithECDSA");
                this.cipher = null;
            }
            this.md = getMessageDigestService(HASHALGO);

            hashAlgOid = new ASN1ObjectIdentifier(HashAlgoType.SHA224.getOid());
        } else {
            this.service = getSignatureService(digestAlgorithmName + "with" + encrAlgorithmName);
            this.cipher = null;
            this.md = null;
            this.hashAlgOid = null;
        }
    }

    private static Signature getSignatureService(
            final String algorithm) {
        Signature service = null;
        if (XipkiNSSProvider.nssProvider != null) {
            try {
                service = Signature.getInstance(algorithm, XipkiNSSProvider.nssProvider);
            } catch (NoSuchAlgorithmException e) {
                try {
                    service = Signature.getInstance(algorithm, "SunEC");
                } catch (NoSuchAlgorithmException | NoSuchProviderException e2) {
                    throw new ProviderException("signature " + algorithm + "not supported");
                }
            }
        }

        if (service == null) {
            final String errorMsg = "unsupported algorithm " + algorithm;
            throw new ProviderException(errorMsg);
        }

        return service;
    }

    private static Cipher getCipherService(
            final String algorithm) {
        Cipher service = null;
        if (XipkiNSSProvider.nssProvider != null) {
            try {
                service = Cipher.getInstance(algorithm, XipkiNSSProvider.nssProvider);
            } catch (NoSuchAlgorithmException e) {
                throw new ProviderException("cipher " + algorithm + " not supported");
            } catch (NoSuchPaddingException e) {
                throw new ProviderException("cipher " + algorithm + " not supported");
            }
        }
        if (service == null) {
            final String errorMsg = "unsupported algorithm " + algorithm;
            throw new ProviderException(errorMsg);
        }

        return service;
    }

    private static MessageDigest getMessageDigestService(
            final String algorithm) {
        MessageDigest service = null;
        if (XipkiNSSProvider.nssProvider != null) {
            try {
                service = MessageDigest.getInstance(algorithm, XipkiNSSProvider.nssProvider);
            } catch (NoSuchAlgorithmException e) {
            }
        }

        if (service == null) {
            final String errorMsg = "could not find any provider for algorithm " + algorithm;
            try {
                service = MessageDigest.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new ProviderException(errorMsg);
            }
        }

        return service;
    }

    @Override
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(
            final String param)
    throws InvalidParameterException {
        if (service != null) {
            return service.getParameter(param);
        } else {
            throw new InvalidParameterException("parametrizing not supported");
        }
    }

    @Override
    protected void engineInitSign(
            final PrivateKey privateKey)
    throws InvalidKeyException {
        if (service != null) {
            service.initSign(privateKey);
        }
        if (cipher != null) {
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        }
        if (md != null) {
            md.reset();
        }
    }

    @Override
    protected void engineInitSign(
            final PrivateKey privateKey,
            final SecureRandom random)
    throws InvalidKeyException {
        if (service != null) {
            service.initSign(privateKey, random);
        }
        if (cipher != null) {
            cipher.init(Cipher.ENCRYPT_MODE, privateKey, random);
        }
        if (md != null) {
            md.reset();
        }
    }

    @Override
    protected void engineInitVerify(
            final PublicKey publicKey)
    throws InvalidKeyException {
        if (service != null) {
            service.initVerify(publicKey);
        }
        if (cipher != null) {
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
        }

        if (md != null) {
            md.reset();
        }
    }

    @Override
    protected void engineSetParameter(
            final AlgorithmParameterSpec params)
    throws InvalidAlgorithmParameterException {
        if (service != null) {
            service.setParameter(params);
        } else {
            throw new InvalidAlgorithmParameterException("unsupported method setParameter");
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(
            final String param,
            final Object value)
    throws InvalidParameterException {
        if (service != null) {
            service.setParameter(param, value);
        } else {
            throw new InvalidParameterException("unsupported method setParameter");
        }
    }

    @Override
    protected byte[] engineSign()
    throws SignatureException {
        if (md != null && service != null) {
            byte[] digest = md.digest();
            service.update(digest);
            return service.sign();
        } else if (service != null) {
            return service.sign();
        } else {
            return encryptHash(md.digest());
        }
    }

    @Override
    protected int engineSign(
            final byte[] outbuf,
            final int offset,
            final int len)
    throws SignatureException {
        if (md != null && service != null) {
            byte[] digest = md.digest();
            service.update(digest);
            return service.sign(outbuf, offset, len);
        } else if (service != null) {
            return service.sign(outbuf, offset, len);
        } else {
            int sigLen = cipher.getOutputSize(1);
            if (sigLen > len) {
                throw new SignatureException("len is less than signature output size");
            }
            if (outbuf.length - offset < sigLen) {
                throw new SignatureException("not enough buffer to save signature");
            }
            byte[] signature = encryptHash(md.digest());
            System.arraycopy(signature, 0, outbuf, offset, signature.length);
            return signature.length;
        }
    }

    private byte[] encryptHash(
            final byte[] hash)
    throws SignatureException {
        int blockSize =    cipher.getOutputSize(1) - 1;

        byte[] tbsHash;

        try {
            AlgorithmIdentifier hashAlgId = new AlgorithmIdentifier(hashAlgOid, DERNull.INSTANCE);
            tbsHash = pkcs1padding(derEncode(hashAlgId, hash), blockSize);
        } catch (IOException e) {
            throw new SignatureException(e.getMessage(), e);
        }

        try {
            return cipher.doFinal(tbsHash);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new SignatureException(e.getMessage(), e);
        }
    }

    @Override
    protected void engineUpdate(
            final byte b)
    throws SignatureException {
        if (md != null) {
            md.update(b);
        } else {
            service.update(b);
        }
    }

    @Override
    protected void engineUpdate(
            final byte[] b,
            final int off,
            final int len)
    throws SignatureException {
        if (md != null) {
            md.update(b, off, len);
        } else {
            service.update(b, off, len);
        }
    }

    @Override
    protected boolean engineVerify(
            final byte[] sigBytes)
    throws SignatureException {
        if (md != null && service != null) {
            byte[] digest = md.digest();
            service.update(digest);
            return service.verify(sigBytes);
        } else if (service != null) {
            return service.verify(sigBytes);
        } else {
            byte[] encodedHash;
            try {
                encodedHash = decodePkcs11Block(cipher.doFinal(sigBytes),
                        cipher.getOutputSize(1) - 1);
            } catch (Exception e) {
                throw new SignatureException(e.getMessage(), e);
            }

            byte[] hash = md.digest();

            ASN1InputStream ain = null;
            try {
                ain = new ASN1InputStream(encodedHash);
                ASN1Encodable obj = ain.readObject();
                if (obj instanceof ASN1Sequence) {
                    DigestInfo di = new DigestInfo((ASN1Sequence) obj);
                    if (di.getAlgorithmId().getAlgorithm().equals(hashAlgOid)) {
                        ASN1Encodable params = di.getAlgorithmId().getParameters();
                        if (params == null || params.equals(DERNull.INSTANCE)) {
                            return Arrays.equals(hash, di.getDigest());
                        }
                    }
                }
            } catch (IOException e) {
                throw new SignatureException(e.getMessage(), e);
            } finally {
                if (ain != null) {
                    try {
                        ain.close();
                    } catch (IOException e) {
                    }
                }
            }

            return false;
        }
    }

    private static byte[] pkcs1padding(
            final byte[] in,
            final int blockSize) {
        int inLen = in.length;
        if (inLen > blockSize) {
            throw new IllegalArgumentException("input data too large");
        }

        byte[]    block = new byte[blockSize];

        block[0] = 0x01;                                                // type code 1
        for (int i = 1; i != block.length - inLen - 1; i++) {
            block[i] = (byte) 0xFF;
        }

        block[block.length - inLen - 1] = 0x00;             // mark the end of the padding
        System.arraycopy(in, 0, block, block.length - inLen, inLen);
        return block;
    }

    private static byte[] decodePkcs11Block(
            final byte[] block,
            final int minLen)
    throws InvalidCipherTextException {
        int offset = 0;
        while (block[offset] == 0) {
            offset++;
        }

        if (block.length - offset < minLen) {
            throw new InvalidCipherTextException("block truncated");
        }

        byte type = block[offset];

        if (type != 1) {
            throw new InvalidCipherTextException("unknown block type");
        }

        // find and extract the message block.
        int start;
        for (start = offset + 1; start != block.length; start++) {
            byte pad = block[start];
            if (pad == 0) {
                break;
            }
            if (pad != (byte) 0xff) {
                throw new InvalidCipherTextException("block padding incorrect");
            }
        }

        start++;                     // data should start at the next byte

        final int HEADER_LENGTH = 10;

        if (start > block.length || start < HEADER_LENGTH) {
            throw new InvalidCipherTextException("no data in block");
        }

        byte[] result = new byte[block.length - start];
        System.arraycopy(block, start, result, 0, result.length);

        return result;
    }

    private static byte[] derEncode(
            final AlgorithmIdentifier algId,
            final byte[] hash)
    throws IOException {
        if (algId == null) {
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

    public static class SHA1withRSA extends NSSSignatureSpi {
        public SHA1withRSA() {
            super(SHA1, RSA);
        }
    }

    public static class SHA224withRSA extends NSSSignatureSpi {
        public SHA224withRSA() {
            super(SHA224, RSA);
        }
    }

    public static class SHA256withRSA extends NSSSignatureSpi {
        public SHA256withRSA() {
            super(SHA256, RSA);
        }
    }

    public static class SHA384withRSA extends NSSSignatureSpi {
        public SHA384withRSA() {
            super(SHA384, RSA);
        }
    }

    public static class SHA512withRSA extends NSSSignatureSpi {
        public SHA512withRSA() {
            super(SHA512, RSA);
        }
    }

    public static class SHA1withECDSA extends NSSSignatureSpi {
        public SHA1withECDSA() {
            super(SHA1, ECDSA);
        }
    }

    public static class SHA256withECDSA extends NSSSignatureSpi {
        public SHA256withECDSA() {
            super(SHA256, ECDSA);
        }
    }

    public static class SHA384withECDSA extends NSSSignatureSpi {
        public SHA384withECDSA() {
            super(SHA384, ECDSA);
        }
    }

    public static class SHA512withECDSA extends NSSSignatureSpi {
        public SHA512withECDSA() {
            super(SHA512, ECDSA);
        }
    }

    public static class RawECDSA extends NSSSignatureSpi {
        public RawECDSA() {
            super("NONEwith" + ECDSA);
        }
    }

    public static class SHA224withECDSA extends NSSSignatureSpi {
        public SHA224withECDSA() {
            super(SHA224, ECDSA);
        }
    }

}
