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

package org.xipki.commons.security;

import java.io.IOException;
import java.math.BigInteger;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.xipki.commons.security.bcext.BcRSAContentVerifierProviderBuilder;
import org.xipki.commons.security.bcext.ECDSAContentVerifierProviderBuilder;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class KeyUtil {

    private static final DefaultDigestAlgorithmIdentifierFinder DFLT_DIGESTALG_IDENTIFIER_FINDER =
            new DefaultDigestAlgorithmIdentifierFinder();

    private static final Map<String, BcContentVerifierProviderBuilder> VERIFIER_PROVIDER_BUILDER
        = new HashMap<>();

    private static final Map<String, KeyFactory> KEY_FACTORIES = new HashMap<>();

    private KeyUtil() {
    }

    public static ContentVerifierProvider getContentVerifierProvider(
            final PublicKey publicKey)
    throws OperatorCreationException, InvalidKeyException {
        String keyAlg = publicKey.getAlgorithm().toUpperCase();
        if (keyAlg.equals("EC")) {
            keyAlg = "ECDSA";
        }

        BcContentVerifierProviderBuilder builder = VERIFIER_PROVIDER_BUILDER.get(keyAlg);
        if (builder == null) {
            if ("RSA".equals(keyAlg)) {
                builder = new BcRSAContentVerifierProviderBuilder(DFLT_DIGESTALG_IDENTIFIER_FINDER);
            } else if ("DSA".equals(keyAlg)) {
                builder = new BcDSAContentVerifierProviderBuilder(DFLT_DIGESTALG_IDENTIFIER_FINDER);
            } else if ("ECDSA".equals(keyAlg)) {
                builder = new ECDSAContentVerifierProviderBuilder(DFLT_DIGESTALG_IDENTIFIER_FINDER);
            } else {
                throw new OperatorCreationException("unknown key algorithm of the public key "
                        + keyAlg);
            }
            VERIFIER_PROVIDER_BUILDER.put(keyAlg, builder);
        }

        AsymmetricKeyParameter keyParam = KeyUtil.generatePublicKeyParameter(publicKey);
        return builder.build(keyParam);
    }

    public static KeyPair generateRSAKeypair(
            final int keysize,
            final SecureRandom random)
    throws Exception {
        return generateRSAKeypair(keysize, (BigInteger) null, random);
    }

    public static KeyPair generateRSAKeypair(
            final int keysize,
            final BigInteger publicExponent,
            final SecureRandom random)
    throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        BigInteger localPublicExponent = publicExponent;
        if (localPublicExponent == null) {
            localPublicExponent = RSAKeyGenParameterSpec.F4;
        }
        AlgorithmParameterSpec params = new RSAKeyGenParameterSpec(keysize, localPublicExponent);
        if (random == null) {
            kpGen.initialize(params);
        } else {
            kpGen.initialize(params, random);
        }
        return kpGen.generateKeyPair();
    }

    public static KeyPair generateDSAKeypair(
            final int pLength,
            final int qLength,
            final SecureRandom random)
    throws Exception {
        return generateDSAKeypair(pLength, qLength, 80, random);
    }

    public static KeyPair generateDSAKeypair(
            final int pLength,
            final int qLength,
            final int certainty,
            final SecureRandom random)
    throws Exception {
        DSAParametersGenerator paramGen = new DSAParametersGenerator(new SHA512Digest());
        DSAParameterGenerationParameters genParams = new DSAParameterGenerationParameters(
                pLength, qLength, certainty, random);
        paramGen.init(genParams);
        DSAParameters dsaParams = paramGen.generateParameters();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", "BC");
        DSAParameterSpec dsaParamSpec = new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(),
                dsaParams.getG());
        kpGen.initialize(dsaParamSpec, random);
        return kpGen.generateKeyPair();
    }

    public static KeyPair generateECKeypair(
            final ASN1ObjectIdentifier curveId,
            final SecureRandom random)
    throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveId.getId());
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
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new InvalidKeySpecException("could not find KeyFactory for " + algorithm
                        + ": " + e.getMessage());
            }
            KEY_FACTORIES.put(algorithm, kf);
            return kf;
        }
    }

    public static PublicKey generatePublicKey(
            final SubjectPublicKeyInfo pkInfo)
    throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keyspec;
        try {
            keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
        } catch (IOException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
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

    public static RSAPublicKey generateRSAPublicKey(
            final BigInteger modulus,
            final BigInteger publicExponent)
    throws InvalidKeySpecException {
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory kf = getKeyFactory("RSA");
        return (RSAPublicKey) kf.generatePublic(keySpec);
    }

    public static ECPublicKey generateECPublicKey(
            final String curveOid,
            final byte[] encodedQ)
    throws InvalidKeySpecException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveOid);
        ECPoint q = spec.getCurve().decodePoint(encodedQ);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(q, spec);

        KeyFactory kf = getKeyFactory("EC");
        return (ECPublicKey) kf.generatePublic(keySpec);
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(
            final PrivateKey key)
    throws InvalidKeyException {
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey k = (RSAPrivateCrtKey) key;

            return new RSAPrivateCrtKeyParameters(k.getModulus(),
                k.getPublicExponent(), k.getPrivateExponent(),
                k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(),
                k.getPrimeExponentQ(), k.getCrtCoefficient());
        } else if (key instanceof RSAPrivateKey) {
            RSAPrivateKey k = (RSAPrivateKey) key;

            return new RSAKeyParameters(true, k.getModulus(), k.getPrivateExponent());
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
        if (key instanceof RSAPublicKey) {
            RSAPublicKey k = (RSAPublicKey) key;
            return new RSAKeyParameters(false, k.getModulus(), k.getPublicExponent());
        } else if (key instanceof ECPublicKey) {
            return ECUtil.generatePublicKeyParameter(key);
        } else if (key instanceof DSAPublicKey) {
            return DSAUtil.generatePublicKeyParameter(key);
        } else {
            throw new InvalidKeyException("unknown key " + key.getClass().getName());
        }
    }

    /**
     * Create a SubjectPublicKeyInfo public key.
     *
     * @param publicKey the SubjectPublicKeyInfo encoding
     * @return the appropriate key parameter
     * @throws java.io.IOException on an error encoding the key
     */
    public static SubjectPublicKeyInfo creatDSASubjectPublicKeyInfo(
            final DSAPublicKey publicKey)
    throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(publicKey.getParams().getP()));
        v.add(new ASN1Integer(publicKey.getParams().getQ()));
        v.add(new ASN1Integer(publicKey.getParams().getG()));
        ASN1Sequence dssParams = new DERSequence(v);

        return new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, dssParams),
                new ASN1Integer(publicKey.getY()));
    }

    public static ASN1ObjectIdentifier getCurveOid(
            final String curveName) {
        ASN1ObjectIdentifier curveOID = X962NamedCurves.getOID(curveName);
        if (curveOID == null) {
            curveOID = SECNamedCurves.getOID(curveName);
        }
        if (curveOID == null) {
            curveOID = TeleTrusTNamedCurves.getOID(curveName);
        }
        if (curveOID == null) {
            curveOID = NISTNamedCurves.getOID(curveName);
        }

        return curveOID;
    }

    public static String getCurveName(
            final ASN1ObjectIdentifier curveOID) {
        String curveName = X962NamedCurves.getName(curveOID);
        if (curveName == null) {
            curveName = SECNamedCurves.getName(curveOID);
        }
        if (curveName == null) {
            curveName = TeleTrusTNamedCurves.getName(curveOID);
        }
        if (curveName == null) {
            curveName = NISTNamedCurves.getName(curveOID);
        }

        return curveName;
    }

    public static Map<String, ASN1ObjectIdentifier> getCurveNameOidMap() {
        Map<String, ASN1ObjectIdentifier> map = new HashMap<>();
        Enumeration<?> names = X962NamedCurves.getNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            ASN1ObjectIdentifier oid = X962NamedCurves.getOID(name);
            if (oid != null) {
                map.put(name, oid);
            }
        }

        names = SECNamedCurves.getNames();

        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            ASN1ObjectIdentifier oid = SECNamedCurves.getOID(name);
            if (oid != null) {
                map.put(name, oid);
            }
        }

        names = TeleTrusTNamedCurves.getNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            ASN1ObjectIdentifier oid = TeleTrusTNamedCurves.getOID(name);
            if (oid != null) {
                map.put(name, oid);
            }
        }

        names = NISTNamedCurves.getNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            ASN1ObjectIdentifier oid = NISTNamedCurves.getOID(name);
            if (oid != null) {
                map.put(name, oid);
            }
        }

        return map;
    } // method getCurveNameOIDMap

}
