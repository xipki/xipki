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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.operator.bc.BcDigestProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.xipki.commons.security.api.SignerException;

/**
 * utility class for converting java.security RSA objects into their
 * org.bouncycastle.crypto counterparts.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SignerUtil {

    private SignerUtil() {
    }

    public static RSAKeyParameters generateRSAPublicKeyParameter(
            final RSAPublicKey key) {
        return new RSAKeyParameters(false, key.getModulus(), key.getPublicExponent());

    }

    public static RSAKeyParameters generateRSAPrivateKeyParameter(
            final RSAPrivateKey key) {
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey k = (RSAPrivateCrtKey) key;

            return new RSAPrivateCrtKeyParameters(k.getModulus(), k.getPublicExponent(),
                    k.getPrivateExponent(), k.getPrimeP(), k.getPrimeQ(),
                    k.getPrimeExponentP(), k.getPrimeExponentQ(), k.getCrtCoefficient());
        } else {
            RSAPrivateKey k = key;

            return new RSAKeyParameters(true, k.getModulus(), k.getPrivateExponent());
        }
    }

    public static PSSSigner createPSSRSASigner(
            final AlgorithmIdentifier sigAlgId)
    throws OperatorCreationException {
        return createPSSRSASigner(sigAlgId, null);
    }

    public static PSSSigner createPSSRSASigner(
            final AlgorithmIdentifier sigAlgId,
            final AsymmetricBlockCipher cipher)
    throws OperatorCreationException {
        if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgId.getAlgorithm())) {
            throw new OperatorCreationException("signature algorithm " + sigAlgId.getAlgorithm()
                + " is not allowed");
        }

        BcDigestProvider digestProvider = BcDefaultDigestProvider.INSTANCE;
        AlgorithmIdentifier digAlgId;
        try {
            digAlgId = AlgorithmUtil.extractDigesetAlgorithmIdentifier(sigAlgId);
        } catch (NoSuchAlgorithmException e) {
            throw new OperatorCreationException(e.getMessage(), e);
        }
        Digest dig = digestProvider.get(digAlgId);

        RSASSAPSSparams param = RSASSAPSSparams.getInstance(sigAlgId.getParameters());

        AlgorithmIdentifier mfgDigAlgId = AlgorithmIdentifier.getInstance(
                param.getMaskGenAlgorithm().getParameters());
        Digest mfgDig = digestProvider.get(mfgDigAlgId);

        int saltSize = param.getSaltLength().intValue();
        int trailerField = param.getTrailerField().intValue();

        AsymmetricBlockCipher localCipher = (cipher == null)
                ? new RSABlindedEngine()
                : cipher;

        return new PSSSigner(localCipher, dig, mfgDig, saltSize, getTrailer(trailerField));
    }

    private static byte getTrailer(
            final int trailerField) {
        if (trailerField == 1) {
            return org.bouncycastle.crypto.signers.PSSSigner.TRAILER_IMPLICIT;
        }

        throw new IllegalArgumentException("unknown trailer field");
    }

    public static boolean verifyPopo(
            final CertificationRequest p10Request) {
        PKCS10CertificationRequest p10Req = new PKCS10CertificationRequest(p10Request);
        return verifyPopo(p10Req);
    }

    public static boolean verifyPopo(
            final PKCS10CertificationRequest p10Request) {
        try {
            SubjectPublicKeyInfo pkInfo = p10Request.getSubjectPublicKeyInfo();
            PublicKey pk = KeyUtil.generatePublicKey(pkInfo);

            ContentVerifierProvider cvp = KeyUtil.getContentVerifierProvider(pk);
            return p10Request.isSignatureValid(cvp);
        } catch (OperatorCreationException | InvalidKeyException | PKCSException
                | NoSuchAlgorithmException | InvalidKeySpecException e) {
            return false;
        }
    }

    public static byte[] pkcs1padding(
            final byte[] in,
            final int blockSize)
    throws SignerException {
        int inLen = in.length;

        if (inLen + 3 > blockSize) {
            throw new SignerException("data too long (maximal " + (blockSize - 3) + " allowed): "
                    + inLen);
        }

        byte[] block = new byte[blockSize];

        block[0] = 0x00;
        // type code 1
        block[1] = 0x01;

        for (int i = 2; i != block.length - inLen - 1; i++) {
            block[i] = (byte) 0xFF;
        }

        // mark the end of the padding
        block[block.length - inLen - 1] = 0x00;
        System.arraycopy(in, 0, block, block.length - inLen, inLen);
        return block;
    }

    public static byte[] convertPlainDSASigX962(
            final byte[] signature)
    throws SignerException {
        byte[] ba = new byte[signature.length / 2];
        ASN1EncodableVector sigder = new ASN1EncodableVector();

        System.arraycopy(signature, 0, ba, 0, ba.length);
        sigder.add(new ASN1Integer(new BigInteger(1, ba)));

        System.arraycopy(signature, ba.length, ba, 0, ba.length);
        sigder.add(new ASN1Integer(new BigInteger(1, ba)));

        DERSequence seq = new DERSequence(sigder);
        try {
            return seq.getEncoded();
        } catch (IOException e) {
            throw new SignerException("IOException, message: " + e.getMessage(), e);
        }
    }

    public static byte[] convertX962DSASigToPlain(
            final byte[] x962Signature,
            final int keyBitLen)
    throws SignerException {
        final int blockSize = (keyBitLen + 7) / 8;
        ASN1Sequence seq = ASN1Sequence.getInstance(x962Signature);
        if (seq.size() != 2) {
            throw new IllegalArgumentException("invalid X962Signature");
        }
        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue();
        int rBitLen = r.bitLength();
        int sBitLen = s.bitLength();
        int bitLen = Math.max(rBitLen, sBitLen);
        if ((bitLen + 7) / 8 > blockSize) {
            throw new SignerException("signature is too large");
        }

        byte[] plainSignature = new byte[2 * blockSize];

        byte[] bytes = r.toByteArray();
        int srcOffset = Math.max(0, bytes.length - blockSize);
        System.arraycopy(bytes, srcOffset, plainSignature, 0, bytes.length - srcOffset);

        bytes = s.toByteArray();
        srcOffset = Math.max(0, bytes.length - blockSize);
        System.arraycopy(bytes, srcOffset, plainSignature, blockSize, bytes.length - srcOffset);
        return plainSignature;
    }

}
