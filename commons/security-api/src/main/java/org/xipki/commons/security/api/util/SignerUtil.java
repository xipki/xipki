/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.api.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.HashAlgoType;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.SecurityException;

/**
 * utility class for converting java.security RSA objects into their
 * org.bouncycastle.crypto counterparts.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerUtil {

    private static final Map<HashAlgoType, byte[]> digestPkcsPrefix = new HashMap<>();

    static {
        digestPkcsPrefix.put(HashAlgoType.SHA1,
                Hex.decode("3021300906052b0e03021a05000414"));
        digestPkcsPrefix.put(HashAlgoType.SHA224,
                Hex.decode("302d300d06096086480165030402040500041c"));
        digestPkcsPrefix.put(HashAlgoType.SHA256,
                Hex.decode("3031300d060960864801650304020105000420"));
        digestPkcsPrefix.put(HashAlgoType.SHA384,
                Hex.decode("3041300d060960864801650304020205000430"));
        digestPkcsPrefix.put(HashAlgoType.SHA512,
                Hex.decode("3051300d060960864801650304020305000440"));
    }

    private SignerUtil() {
    }

    // CHECKSTYLE:SKIP
    public static RSAKeyParameters generateRSAPublicKeyParameter(
            final RSAPublicKey key) {
        ParamUtil.requireNonNull("key", key);
        return new RSAKeyParameters(false, key.getModulus(), key.getPublicExponent());

    }

    // CHECKSTYLE:SKIP
    public static RSAKeyParameters generateRSAPrivateKeyParameter(
            final RSAPrivateKey key) {
        ParamUtil.requireNonNull("key", key);
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;

            return new RSAPrivateCrtKeyParameters(rsaKey.getModulus(), rsaKey.getPublicExponent(),
                    rsaKey.getPrivateExponent(), rsaKey.getPrimeP(), rsaKey.getPrimeQ(),
                    rsaKey.getPrimeExponentP(), rsaKey.getPrimeExponentQ(),
                    rsaKey.getCrtCoefficient());
        } else {
            return new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent());
        }
    }

    // CHECKSTYLE:SKIP
    public static PSSSigner createPSSRSASigner(
            final AlgorithmIdentifier sigAlgId)
    throws SecurityException {
        return createPSSRSASigner(sigAlgId, null);
    }

    // CHECKSTYLE:SKIP
    public static PSSSigner createPSSRSASigner(
            final AlgorithmIdentifier sigAlgId,
            final AsymmetricBlockCipher cipher)
    throws SecurityException {
        ParamUtil.requireNonNull("sigAlgId", sigAlgId);
        if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgId.getAlgorithm())) {
            throw new SecurityException("signature algorithm " + sigAlgId.getAlgorithm()
                + " is not allowed");
        }

        AlgorithmIdentifier digAlgId;
        try {
            digAlgId = AlgorithmUtil.extractDigesetAlgorithmIdentifier(sigAlgId);
        } catch (NoSuchAlgorithmException ex) {
            throw new SecurityException(ex.getMessage(), ex);
        }

        RSASSAPSSparams param = RSASSAPSSparams.getInstance(sigAlgId.getParameters());

        AlgorithmIdentifier mfgDigAlgId = AlgorithmIdentifier.getInstance(
                param.getMaskGenAlgorithm().getParameters());

        Digest dig = getDigest(digAlgId);
        Digest mfgDig = getDigest(mfgDigAlgId);

        int saltSize = param.getSaltLength().intValue();
        int trailerField = param.getTrailerField().intValue();

        AsymmetricBlockCipher tmpCipher = (cipher == null)
                ? new RSABlindedEngine()
                : cipher;

        return new PSSSigner(tmpCipher, dig, mfgDig, saltSize, getTrailer(trailerField));
    }

    private static byte getTrailer(
            final int trailerField) {
        if (trailerField == 1) {
            return org.bouncycastle.crypto.signers.PSSSigner.TRAILER_IMPLICIT;
        }

        throw new IllegalArgumentException("unknown trailer field");
    }

    // CHECKSTYLE:SKIP
    public static byte[] EMSA_PKCS1_v1_5_encoding(
            final byte[] hashValue,
            final int modulusBigLength,
            final HashAlgoType hashAlgo)
    throws SecurityException {
        ParamUtil.requireNonNull("hashValue", hashValue);
        ParamUtil.requireNonNull("hashAlgo", hashAlgo);

        final int hashLen = hashAlgo.getLength();
        ParamUtil.requireRange("hashValue.length", hashValue.length, hashLen, hashLen);

        int blockSize = (modulusBigLength + 7) / 8;
        byte[] prefix = digestPkcsPrefix.get(hashAlgo);

        if (prefix.length + hashLen + 3 > blockSize) {
            throw new SecurityException("data too long (maximal " + (blockSize - 3)
                    + " allowed): " + (prefix.length + hashLen));
        }

        byte[] block = new byte[blockSize];

        block[0] = 0x00;
        // type code 1
        block[1] = 0x01;

        int offset = 2;
        while (offset < block.length - prefix.length - hashLen - 1) {
            block[offset++] = (byte) 0xFF;
        }
        // mark the end of the padding
        block[offset] = 0x00;

        System.arraycopy(prefix, 0, block, offset, prefix.length);
        offset += prefix.length;
        System.arraycopy(hashValue, 0, block, offset, hashValue.length);
        return block;
    }

    // CHECKSTYLE:SKIP
    public static byte[] EMSA_PKCS1_v1_5_encoding(
            final byte[] encodedDigestInfo,
            final int modulusBigLength)
    throws SecurityException {
        ParamUtil.requireNonNull("encodedDigestInfo", encodedDigestInfo);

        int msgLen = encodedDigestInfo.length;
        int blockSize = (modulusBigLength + 7) / 8;

        if (msgLen + 3 > blockSize) {
            throw new SecurityException("data too long (maximal " + (blockSize - 3)
                    + " allowed): " + msgLen);
        }

        byte[] block = new byte[blockSize];

        block[0] = 0x00;
        // type code 1
        block[1] = 0x01;

        int offset = 2;
        while (offset < block.length - msgLen - 1) {
            block[offset++] = (byte) 0xFF;
        }
        // mark the end of the padding
        block[offset] = 0x00;

        System.arraycopy(encodedDigestInfo, 0, block, offset, encodedDigestInfo.length);
        return block;
    }

    // CHECKSTYLE:SKIP
    public static byte[] EMSA_PSS_ENCODE(
            final HashAlgoType contentDigest,
            final byte[] hashValue,
            final HashAlgoType mgfDigest,
            final int saltLen,
            final int modulusBigLength,
            final SecureRandom random)
    throws SecurityException {
        final int hLen = contentDigest.getLength();
        final byte[] salt = new byte[saltLen];
        final byte[] mDash = new byte[8 + saltLen + hLen];
        final byte trailer = (byte)0xBC;

        if (hashValue.length != hLen) {
            throw new SecurityException("hashValue.length is incorrect: "
                    + hashValue.length + " != " + hLen);
        }

        int emBits = modulusBigLength - 1;
        if (emBits < (8 * hLen + 8 * saltLen + 9)) {
            throw new IllegalArgumentException("key too small for specified hash and salt lengths");
        }

        System.arraycopy(hashValue, 0, mDash, mDash.length - hLen - saltLen, hLen);

        random.nextBytes(salt);
        System.arraycopy(salt, 0, mDash, mDash.length - saltLen, saltLen);

        byte[] hv = HashCalculator.hash(contentDigest, mDash);

        byte[] block = new byte[(emBits + 7) / 8];
        block[block.length - saltLen - 1 - hLen - 1] = 0x01;
        System.arraycopy(salt, 0, block, block.length - saltLen - hLen - 1, saltLen);

        byte[] dbMask = maskGeneratorFunction1(mgfDigest, hv, block.length - hLen - 1);
        for (int i = 0; i != dbMask.length; i++) {
            block[i] ^= dbMask[i];
        }

        block[0] &= (0xff >> ((block.length * 8) - emBits));

        System.arraycopy(hv, 0, block, block.length - hLen - 1, hLen);

        block[block.length - 1] = trailer;
        return block;
    }

    /**
     * int to octet string.
     */
    private static void ItoOSP( // CHECKSTYLE:SKIP
        final int i, // CHECKSTYLE:SKIP
        final byte[] sp,
        final int spOffset) {
        sp[spOffset + 0] = (byte)(i >>> 24);
        sp[spOffset + 1] = (byte)(i >>> 16);
        sp[spOffset + 2] = (byte)(i >>> 8);
        sp[spOffset + 3] = (byte)(i >>> 0);
    }

    /**
     * mask generator function, as described in PKCS1v2.
     */
    private static byte[] maskGeneratorFunction1(
        final HashAlgoType mgfDigest,
        final byte[] Z, // CHECKSTYLE:SKIP
        final int length) {
        int mgfhLen = mgfDigest.getLength();
        byte[] mask = new byte[length];
        int counter = 0;

        byte[] all = new byte[Z.length + 4];
        System.arraycopy(Z, 0, all, 0, Z.length);

        while (counter < (length / mgfhLen)) {
            ItoOSP(counter, all, Z.length);
            byte[] hashBuf = HashCalculator.hash(mgfDigest, all);
            System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mgfhLen);
            counter++;
        }

        if ((counter * mgfhLen) < length) {
            ItoOSP(counter, all, Z.length);
            byte[] hashBuf = HashCalculator.hash(mgfDigest, all);
            System.arraycopy(hashBuf, 0, mask, counter * mgfhLen,
                    mask.length - (counter * mgfhLen));
        }

        return mask;
    }

    // CHECKSTYLE:SKIP
    public static byte[] convertPlainDSASigToX962(
            final byte[] signature)
    throws SecurityException {
        ParamUtil.requireNonNull("signature", signature);
        byte[] ba = new byte[signature.length / 2];
        ASN1EncodableVector sigder = new ASN1EncodableVector();

        System.arraycopy(signature, 0, ba, 0, ba.length);
        sigder.add(new ASN1Integer(new BigInteger(1, ba)));

        System.arraycopy(signature, ba.length, ba, 0, ba.length);
        sigder.add(new ASN1Integer(new BigInteger(1, ba)));

        DERSequence seq = new DERSequence(sigder);
        try {
            return seq.getEncoded();
        } catch (IOException ex) {
            throw new SecurityException("IOException, message: " + ex.getMessage(), ex);
        }
    }

    // CHECKSTYLE:SKIP
    public static byte[] convertX962DSASigToPlain(
            final byte[] x962Signature,
            final int keyBitLen)
    throws SecurityException {
        ParamUtil.requireNonNull("x962Signature", x962Signature);
        final int blockSize = (keyBitLen + 7) / 8;
        ASN1Sequence seq = ASN1Sequence.getInstance(x962Signature);
        if (seq.size() != 2) {
            throw new IllegalArgumentException("invalid X962Signature");
        }
        BigInteger sigR = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue();
        BigInteger sigS = ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue();
        int bitLenOfR = sigR.bitLength();
        int bitLenOfS = sigS.bitLength();
        int bitLen = Math.max(bitLenOfR, bitLenOfS);
        if ((bitLen + 7) / 8 > blockSize) {
            throw new SecurityException("signature is too large");
        }

        byte[] plainSignature = new byte[2 * blockSize];

        byte[] bytes = sigR.toByteArray();
        int srcOffset = Math.max(0, bytes.length - blockSize);
        System.arraycopy(bytes, srcOffset, plainSignature, 0, bytes.length - srcOffset);

        bytes = sigS.toByteArray();
        srcOffset = Math.max(0, bytes.length - blockSize);
        System.arraycopy(bytes, srcOffset, plainSignature, blockSize, bytes.length - srcOffset);
        return plainSignature;
    }

    public static Digest getDigest(
            final AlgorithmIdentifier digestAlgId)
    throws SecurityException {
        try {
            return BcDefaultDigestProvider.INSTANCE.get(digestAlgId);
        } catch (OperatorCreationException ex) {
            throw new SecurityException(
                    "could not get digest for " + digestAlgId.getAlgorithm().getId());
        }
    }

}
