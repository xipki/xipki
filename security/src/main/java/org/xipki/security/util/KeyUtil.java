/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
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
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.BigIntegers;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class KeyUtil {

    private static final Map<String, KeyFactory> KEY_FACTORIES = new HashMap<>();

    private static final Map<String, KeyPairGenerator> KEYPAIR_GENERATORS = new HashMap<>();

    private KeyUtil() {
    }

    public static KeyStore getKeyStore(String storeType)
            throws KeyStoreException, NoSuchProviderException {
        ParamUtil.requireNonBlank("storeType", storeType);
        if ("JKS".equalsIgnoreCase(storeType) || "JCEKS".equalsIgnoreCase(storeType)) {
            return KeyStore.getInstance(storeType);
        } else {
            try {
                return KeyStore.getInstance(storeType, "BC");
            } catch (KeyStoreException | NoSuchProviderException ex) {
                return KeyStore.getInstance(storeType);
            }
        }
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateRSAKeypair(int keysize, BigInteger publicExponent,
            SecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        BigInteger tmpPublicExponent = publicExponent;
        if (tmpPublicExponent == null) {
            tmpPublicExponent = RSAKeyGenParameterSpec.F4;
        }
        AlgorithmParameterSpec params = new RSAKeyGenParameterSpec(keysize, tmpPublicExponent);
        KeyPairGenerator kpGen = getKeyPairGenerator("RSA");
        synchronized (kpGen) {
            if (random == null) {
                kpGen.initialize(params);
            } else {
                kpGen.initialize(params, random);
            }
            return kpGen.generateKeyPair();
        }
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateDSAKeypair(int plength, int qlength, SecureRandom random)
            throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidAlgorithmParameterException {
        DSAParameterSpec dsaParamSpec = DSAParameterCache.getDSAParameterSpec(plength, qlength,
                random);
        KeyPairGenerator kpGen = getKeyPairGenerator("DSA");
        synchronized (kpGen) {
            kpGen.initialize(dsaParamSpec, random);
            return kpGen.generateKeyPair();
        }
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateDSAKeypair(DSAParameters dsaParams, SecureRandom random)
            throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidAlgorithmParameterException {
        DSAParameterSpec dsaParamSpec = new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(),
                dsaParams.getG());
        KeyPairGenerator kpGen = getKeyPairGenerator("DSA");
        synchronized (kpGen) {
            kpGen.initialize(dsaParamSpec, random);
            return kpGen.generateKeyPair();
        }
    }

    // CHECKSTYLE:SKIP
    public static DSAPublicKey generateDSAPublicKey(DSAPublicKeySpec keySpec)
            throws InvalidKeySpecException {
        ParamUtil.requireNonNull("keySpec", keySpec);
        KeyFactory kf = getKeyFactory("DSA");
        synchronized (kf) {
            return (DSAPublicKey) kf.generatePublic(keySpec);
        }
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateECKeypairForCurveNameOrOid(String curveNameOrOid,
            SecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidAlgorithmParameterException {
        ASN1ObjectIdentifier oid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveNameOrOid);
        if (oid == null) {
            throw new IllegalArgumentException("invalid curveNameOrOid '" + curveNameOrOid + "'");
        }
        return generateECKeypair(oid, random);
    }

    // CHECKSTYLE:SKIP
    public static KeyPair generateECKeypair(ASN1ObjectIdentifier curveId, SecureRandom random)
            throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidAlgorithmParameterException {
        ParamUtil.requireNonNull("curveId", curveId);

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveId.getId());
        KeyPairGenerator kpGen = getKeyPairGenerator("EC");
        synchronized (kpGen) {
            if (random == null) {
                kpGen.initialize(spec);
            } else {
                kpGen.initialize(spec, random);
            }
            return kpGen.generateKeyPair();
        }
    }

    private static KeyFactory getKeyFactory(String algorithm) throws InvalidKeySpecException {
        String alg = algorithm.toUpperCase();
        if ("ECDSA".equals(alg)) {
            alg = "EC";
        }
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

    private static KeyPairGenerator getKeyPairGenerator(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        String alg = algorithm.toUpperCase();
        if ("ECDSA".equals(alg)) {
            alg = "EC";
        }
        synchronized (KEYPAIR_GENERATORS) {
            KeyPairGenerator kg = KEYPAIR_GENERATORS.get(algorithm);
            if (kg != null) {
                return kg;
            }

            kg = KeyPairGenerator.getInstance(algorithm, "BC");
            KEYPAIR_GENERATORS.put(algorithm, kg);
            return kg;
        }
    }

    public static PublicKey generatePublicKey(SubjectPublicKeyInfo pkInfo)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        ParamUtil.requireNonNull("pkInfo", pkInfo);

        X509EncodedKeySpec keyspec;
        try {
            keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
        } catch (IOException ex) {
            throw new InvalidKeySpecException(ex.getMessage(), ex);
        }
        ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

        String algorithm;
        if (PKCSObjectIdentifiers.rsaEncryption.equals(aid)) {
            algorithm = "RSA";
        } else if (X9ObjectIdentifiers.id_dsa.equals(aid)) {
            algorithm = "DSA";
        } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(aid)) {
            algorithm = "EC";
        } else {
            throw new InvalidKeySpecException("unsupported key algorithm: " + aid);
        }

        KeyFactory kf = getKeyFactory(algorithm);
        synchronized (kf) {
            return kf.generatePublic(keyspec);
        }
    }

    // CHECKSTYLE:SKIP
    public static RSAPublicKey generateRSAPublicKey(RSAPublicKeySpec keySpec)
            throws InvalidKeySpecException {
        ParamUtil.requireNonNull("keySpec", keySpec);
        KeyFactory kf = getKeyFactory("RSA");
        synchronized (kf) {
            return (RSAPublicKey) kf.generatePublic(keySpec);
        }
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
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

    public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
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

    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(PublicKey publicKey)
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
                throw new InvalidKeyException("Cannot find namedCurve of the given private key");
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
            byte[] wxBytes = BigIntegers.asUnsignedByteArray(keysize, wx);
            byte[] wyBytes = BigIntegers.asUnsignedByteArray(keysize, wy);
            byte[] pubKey = new byte[1 + keysize * 2];
            pubKey[0] = 4; // uncompressed
            System.arraycopy(wxBytes, 0, pubKey, 1, keysize);
            System.arraycopy(wyBytes, 0, pubKey, 1 + keysize, keysize);

            AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                    curveOid);
            return new SubjectPublicKeyInfo(algId, pubKey);
        } else {
            throw new InvalidKeyException(
                    "unknown publicKey class " + publicKey.getClass().getName());
        }
    }

    // CHECKSTYLE:SKIP
    public static ECPublicKey createECPublicKey(byte[] encodedAlgorithmIdParameters,
            byte[] encodedPoint) throws InvalidKeySpecException {
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

    private static ASN1ObjectIdentifier detectCurveOid(ECParameterSpec paramSpec) {
        org.bouncycastle.jce.spec.ECParameterSpec bcParamSpec =
                EC5Util.convertSpec(paramSpec, false);
        return ECUtil.getNamedCurveOid(bcParamSpec);
    }

}
