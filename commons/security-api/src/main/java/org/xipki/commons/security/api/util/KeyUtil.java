/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class KeyUtil {

    private static final Map<String, KeyFactory> KEY_FACTORIES = new HashMap<>();

    private KeyUtil() {
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateRSAKeypair(
            final int keysize,
            final SecureRandom random)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return generateRSAKeypair(keysize, (BigInteger) null, random);
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateRSAKeypair(
            final int keysize,
            final BigInteger publicExponent,
            final SecureRandom random)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        BigInteger tmpPublicExponent = publicExponent;
        if (tmpPublicExponent == null) {
            tmpPublicExponent = RSAKeyGenParameterSpec.F4;
        }
        AlgorithmParameterSpec params = new RSAKeyGenParameterSpec(keysize, tmpPublicExponent);
        if (random == null) {
            kpGen.initialize(params);
        } else {
            kpGen.initialize(params, random);
        }
        return kpGen.generateKeyPair();
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateDSAKeypair(
            final int plength,
            final int qlength,
            final SecureRandom random)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return generateDSAKeypair(plength, qlength, 80, random);
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateDSAKeypair(
            final int plength,
            final int qlength,
            final int certainty,
            final SecureRandom random)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        DSAParametersGenerator paramGen = new DSAParametersGenerator(new SHA512Digest());
        DSAParameterGenerationParameters genParams = new DSAParameterGenerationParameters(
                plength, qlength, certainty, random);
        paramGen.init(genParams);
        DSAParameters dsaParams = paramGen.generateParameters();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", "BC");
        DSAParameterSpec dsaParamSpec = new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(),
                dsaParams.getG());
        kpGen.initialize(dsaParamSpec, random);
        return kpGen.generateKeyPair();
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateDSAKeypair(
            final DSAParameters dsaParams,
            final SecureRandom random)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", "BC");
        DSAParameterSpec dsaParamSpec = new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(),
                dsaParams.getG());
        kpGen.initialize(dsaParamSpec, random);
        return kpGen.generateKeyPair();
    }

    // CHECKSTYLE:SKIP
    public static DSAPublicKey generateDSAPublicKey(
            final DSAPublicKeySpec keySpec)
    throws InvalidKeySpecException {
        ParamUtil.requireNonNull("keySpec", keySpec);
        KeyFactory kf = getKeyFactory("DSA");
        return (DSAPublicKey) kf.generatePublic(keySpec);
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateECKeypairForCurveNameOrOid(
            final String curveNameOrOid,
            final SecureRandom random)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ASN1ObjectIdentifier oid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveNameOrOid);
        if (oid == null) {
            throw new IllegalArgumentException("invalid curveNameOrOid '" + curveNameOrOid + "'");
        }
        return generateECKeypair(oid, random);
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateECKeypair(
            final ASN1ObjectIdentifier curveId,
            final SecureRandom random)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ParamUtil.requireNonNull("curveId", curveId);

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveId.getId());
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");
        if (random == null) {
            kpGen.initialize(spec);
        } else {
            kpGen.initialize(spec, random);
        }
        return kpGen.generateKeyPair();
    }

    private static KeyFactory getKeyFactory(
            final String algorithm)
    throws InvalidKeySpecException {
        synchronized (KEY_FACTORIES) {
            KeyFactory kf = KEY_FACTORIES.get(algorithm);
            if (kf != null) {
                return kf;
            }

            try {
                kf = KeyFactory.getInstance(algorithm, "BC");
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                throw new InvalidKeySpecException("could not find KeyFactory for " + algorithm
                        + ": " + ex.getMessage());
            }
            KEY_FACTORIES.put(algorithm, kf);
            return kf;
        }
    }

    public static PublicKey generatePublicKey(
            final SubjectPublicKeyInfo pkInfo)
    throws NoSuchAlgorithmException, InvalidKeySpecException {
        ParamUtil.requireNonNull("pkInfo", pkInfo);

        X509EncodedKeySpec keyspec;
        try {
            keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
        } catch (IOException ex) {
            throw new InvalidKeySpecException(ex.getMessage(), ex);
        }
        ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

        KeyFactory kf;
        if (PKCSObjectIdentifiers.rsaEncryption.equals(aid)) {
            kf = KeyFactory.getInstance("RSA");
        } else if (X9ObjectIdentifiers.id_dsa.equals(aid)) {
            kf = KeyFactory.getInstance("DSA");
        } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(aid)) {
            kf = KeyFactory.getInstance("ECDSA");
        } else {
            throw new InvalidKeySpecException("unsupported key algorithm: " + aid);
        }

        return kf.generatePublic(keyspec);
    }

    // CHECKSTYLE:SKIP
    public static RSAPublicKey generateRSAPublicKey(
            RSAPublicKeySpec keySpec)
    throws InvalidKeySpecException {
        ParamUtil.requireNonNull("keySpec", keySpec);
        KeyFactory kf = getKeyFactory("RSA");
        return (RSAPublicKey) kf.generatePublic(keySpec);
    }

    // CHECKSTYLE:SKIP
    public static ECPublicKey generateECPublicKeyForNameOrOid(
            final String curveNameOrOid,
            final byte[] encodedQ)
    throws InvalidKeySpecException {
        ASN1ObjectIdentifier oid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveNameOrOid);
        if (oid == null) {
            throw new IllegalArgumentException("invalid curveNameOrOid '" + curveNameOrOid + "'");
        }
        return generateECPublicKey(oid, encodedQ);
    }

    // CHECKSTYLE:SKIP
    public static ECPublicKey generateECPublicKey(
            final ASN1ObjectIdentifier curveOid,
            final byte[] encodedQ)
    throws InvalidKeySpecException {
        ParamUtil.requireNonNull("curveOid", curveOid);
        ParamUtil.requireNonNull("encoded", encodedQ);
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveOid.getId());
        ECPoint pointQ = spec.getCurve().decodePoint(encodedQ);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(pointQ, spec);

        KeyFactory kf = getKeyFactory("EC");
        return (ECPublicKey) kf.generatePublic(keySpec);
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(
            final PrivateKey key)
    throws InvalidKeyException {
        ParamUtil.requireNonNull("key", key);

        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
            return new RSAPrivateCrtKeyParameters(rsaKey.getModulus(),
                rsaKey.getPublicExponent(), rsaKey.getPrivateExponent(),
                rsaKey.getPrimeP(), rsaKey.getPrimeQ(), rsaKey.getPrimeExponentP(),
                rsaKey.getPrimeExponentQ(), rsaKey.getCrtCoefficient());
        } else if (key instanceof RSAPrivateKey) {
            RSAPrivateKey rsaKey = (RSAPrivateKey) key;
            return new RSAKeyParameters(true, rsaKey.getModulus(), rsaKey.getPrivateExponent());
        } else if (key instanceof ECPrivateKey) {
            return ECUtil.generatePrivateKeyParameter(key);
        } else if (key instanceof DSAPrivateKey) {
            return DSAUtil.generatePrivateKeyParameter(key);
        } else {
            throw new InvalidKeyException("unknown key " + key.getClass().getName());
        }
    }

    public static AsymmetricKeyParameter generatePublicKeyParameter(
            final PublicKey key)
    throws InvalidKeyException {
        ParamUtil.requireNonNull("key", key);

        if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) key;
            return new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent());
        } else if (key instanceof ECPublicKey) {
            return ECUtil.generatePublicKeyParameter(key);
        } else if (key instanceof DSAPublicKey) {
            return DSAUtil.generatePublicKeyParameter(key);
        } else {
            throw new InvalidKeyException("unknown key " + key.getClass().getName());
        }
    }

    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(
            final PublicKey publicKey)
    throws InvalidKeyException {
        ParamUtil.requireNonNull("publicKey", publicKey);

        if (publicKey instanceof DSAPublicKey) {
            DSAPublicKey dsaPubKey = (DSAPublicKey) publicKey;
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(new ASN1Integer(dsaPubKey.getParams().getP()));
            vec.add(new ASN1Integer(dsaPubKey.getParams().getQ()));
            vec.add(new ASN1Integer(dsaPubKey.getParams().getG()));
            ASN1Sequence dssParams = new DERSequence(vec);

            try {
                return new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, dssParams),
                        new ASN1Integer(dsaPubKey.getY()));
            } catch (IOException ex) {
                throw new InvalidKeyException(ex.getMessage(), ex);
            }
        } else if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPubKey = (RSAPublicKey) publicKey;
            try {
                return new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
                                DERNull.INSTANCE),
                        new org.bouncycastle.asn1.pkcs.RSAPublicKey(rsaPubKey.getModulus(),
                                rsaPubKey.getPublicExponent()));
            } catch (IOException ex) {
                throw new InvalidKeyException(ex.getMessage(), ex);
            }
        } else if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPubKey = (ECPublicKey) publicKey;

            ECParameterSpec paramSpec = ecPubKey.getParams();
            ASN1ObjectIdentifier curveOid = detectCurveOid(paramSpec);
            if (curveOid == null) {
                throw new InvalidKeyException("Cannot find the name of the given EC public key");
            }

            java.security.spec.ECPoint pointW = ecPubKey.getW();
            BigInteger wx = pointW.getAffineX();
            if (wx.signum() != 1) {
                throw new InvalidKeyException("Wx is not positive");
            }

            BigInteger wy = pointW.getAffineY();
            if (wy.signum() != 1) {
                throw new InvalidKeyException("Wy is not positive");
            }

            int keysize = (paramSpec.getOrder().bitLength() + 7) / 8;
            byte[] wxBytes = wx.toByteArray();
            byte[] wyBytes = wy.toByteArray();
            byte[] pubKey = new byte[1 + keysize * 2];
            pubKey[0] = 4; // uncompressed

            int numBytesToCopy = Math.min(wxBytes.length, keysize);
            int srcOffset = Math.max(0, wxBytes.length - numBytesToCopy);
            int destOffset = 1 + Math.max(0, keysize - wxBytes.length);
            System.arraycopy(wxBytes, srcOffset, pubKey, destOffset, numBytesToCopy);

            numBytesToCopy = Math.min(wyBytes.length, keysize);
            srcOffset = Math.max(0, wyBytes.length - numBytesToCopy);
            destOffset = 1 + keysize + Math.max(0, keysize - wyBytes.length);
            System.arraycopy(wyBytes, srcOffset, pubKey, destOffset, numBytesToCopy);

            AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                    curveOid);
            return new SubjectPublicKeyInfo(algId, pubKey);
        } else {
            throw new InvalidKeyException(
                    "unknown publicKey class " + publicKey.getClass().getName());
        }
    }

    // CHECKSTYLE:SKIP
    public static ECPublicKey createECPublicKey(
            byte[] encodedAlgorithmIdParameters,
            byte[] encodedPoint)
    throws InvalidKeySpecException {
        ParamUtil.requireNonNull("encodedAlgorithmIdParameters", encodedAlgorithmIdParameters);
        ParamUtil.requireNonNull("encodedPoint", encodedPoint);

        ASN1Encodable algParams;
        if (encodedAlgorithmIdParameters[0] == 6) {
            algParams = ASN1ObjectIdentifier.getInstance(encodedAlgorithmIdParameters);
        } else {
            algParams = X962Parameters.getInstance(encodedAlgorithmIdParameters);
        }
        AlgorithmIdentifier algId = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey, algParams);

        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, encodedPoint);
        X509EncodedKeySpec keySpec;
        try {
            keySpec = new X509EncodedKeySpec(spki.getEncoded());
        } catch (IOException ex) {
            throw new InvalidKeySpecException(ex.getMessage(), ex);
        }

        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("EC", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new InvalidKeySpecException(ex.getMessage(), ex);
        }
        return (ECPublicKey) kf.generatePublic(keySpec);
    }

    private static ASN1ObjectIdentifier detectCurveOid(
            final ECParameterSpec paramSpec) {
        org.bouncycastle.jce.spec.ECParameterSpec bcParamSpec =
                EC5Util.convertSpec(paramSpec, false);
        return ECUtil.getNamedCurveOid(bcParamSpec);
    }

}
