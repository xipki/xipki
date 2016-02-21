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

package org.xipki.commons.security.p12;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.xipki.commons.security.api.p12.P12KeypairGenerationResult;
import org.xipki.commons.security.api.p12.P12KeypairGenerator;
import org.xipki.commons.security.api.p12.P12KeystoreGenerationParameters;
import org.xipki.commons.security.api.util.KeyUtil;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.commons.security.bcext.ECDSAContentSignerBuilder;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P12KeypairGeneratorImpl implements P12KeypairGenerator {

    private static class KeyPairWithSubjectPublicKeyInfo {

        private KeyPair keypair;

        private SubjectPublicKeyInfo subjectPublicKeyInfo;

        KeyPairWithSubjectPublicKeyInfo(
                final KeyPair keypair,
                final SubjectPublicKeyInfo subjectPublicKeyInfo)
        throws InvalidKeySpecException {
            super();
            this.keypair = keypair;
            this.subjectPublicKeyInfo = X509Util.toRfc3279Style(subjectPublicKeyInfo);
        }

        public KeyPair getKeypair() {
            return keypair;
        }

        public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
            return subjectPublicKeyInfo;
        }

    } // class KeyPairWithSubjectPublicKeyInfo

    static class KeyAndCertPair {

        private final X509CertificateHolder cert;

        private final X509Certificate jceCert;

        private final PrivateKey key;

        KeyAndCertPair(
                final X509CertificateHolder cert,
                final PrivateKey key)
        throws CertificateParsingException {
            this.cert = cert;
            this.key = key;
            this.jceCert = new X509CertificateObject(cert.toASN1Structure());
        }

        public X509CertificateHolder getCert() {
            return cert;
        }

        public Certificate getJceCert() {
            return jceCert;
        }

        public PrivateKey getKey() {
            return key;
        }

    } // class KeyAndCertPair

    private static final long MIN = 60L * 1000;

    private static final long DAY = 24L * 60 * 60 * 1000;

    public P12KeypairGeneratorImpl()
    throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public P12KeypairGenerationResult generateRSAKeypair(
            final int keysize,
            final BigInteger publicExponent,
            final P12KeystoreGenerationParameters params)
    throws Exception {
        KeyPairWithSubjectPublicKeyInfo kp = genRSAKeypair(keysize, publicExponent,
                params.getRandom());
        return generateIdentity(kp, params);
    }

    @Override
    public P12KeypairGenerationResult generateDSAKeypair(
            final int pLength,
            final int qLength,
            final P12KeystoreGenerationParameters params)
    throws Exception {
        KeyPairWithSubjectPublicKeyInfo kp = genDSAKeypair(pLength, qLength, params.getRandom());
        return generateIdentity(kp, params);
    }

    @Override
    public P12KeypairGenerationResult generateECKeypair(
            final String curveNameOrOid,
            final P12KeystoreGenerationParameters params)
    throws Exception {
        KeyPairWithSubjectPublicKeyInfo kp = genECKeypair(curveNameOrOid, params.getRandom());
        return generateIdentity(kp, params);
    }

    private KeyPairWithSubjectPublicKeyInfo genECKeypair(
            final String curveNameOrOid,
            final SecureRandom random)
    throws Exception {
        ASN1ObjectIdentifier curveOid = KeyUtil.getCurveOidForCurveNameOrOid(curveNameOrOid);
        if (curveOid == null) {
            throw new IllegalArgumentException("invalid curveNameOrOid '" + curveNameOrOid + "'");
        }
        KeyPair kp = KeyUtil.generateECKeypair(curveOid, random);
        AlgorithmIdentifier algId = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey, curveOid);
        BCECPublicKey pub = (BCECPublicKey) kp.getPublic();
        byte[] keyData = pub.getQ().getEncoded(false);
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algId, keyData);

        return new KeyPairWithSubjectPublicKeyInfo(kp, subjectPublicKeyInfo);
    }

    private KeyPairWithSubjectPublicKeyInfo genRSAKeypair(
            final int keysize,
            final BigInteger publicExponent,
            final SecureRandom random)
    throws Exception {
        KeyPair kp = KeyUtil.generateRSAKeypair(keysize, publicExponent, random);
        java.security.interfaces.RSAPublicKey rsaPubKey =
                (java.security.interfaces.RSAPublicKey) kp.getPublic();

        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                new RSAPublicKey(rsaPubKey.getModulus(), rsaPubKey.getPublicExponent()));
        return new KeyPairWithSubjectPublicKeyInfo(kp, spki);
    }

    private KeyPairWithSubjectPublicKeyInfo genDSAKeypair(
            final int pLength,
            final int qLength,
            final SecureRandom random)
    throws Exception {
        KeyPair kp = KeyUtil.generateDSAKeypair(pLength, qLength, random);
        SubjectPublicKeyInfo spki = KeyUtil.creatDSASubjectPublicKeyInfo(
                (DSAPublicKey) kp.getPublic());
        return new KeyPairWithSubjectPublicKeyInfo(kp, spki);
    }

    private static P12KeypairGenerationResult generateIdentity(
            final KeyPairWithSubjectPublicKeyInfo kp,
            final P12KeystoreGenerationParameters params)
    throws Exception {
        Date now = new Date();
        Date notBefore = new Date(now.getTime() - 10 * MIN); // 10 minutes past
        Date notAfter = new Date(notBefore.getTime() + 3650 * DAY);

        X500Name subjectDN = new X500Name("CN=DUMMY");
        SubjectPublicKeyInfo subjectPublicKeyInfo = kp.getSubjectPublicKeyInfo();
        ContentSigner contentSigner = getContentSigner(kp.getKeypair().getPrivate());

        // Generate keystore
        X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(subjectDN,
                BigInteger.valueOf(1), notBefore, notAfter, subjectDN, subjectPublicKeyInfo);

        KeyAndCertPair identity = new KeyAndCertPair(certGenerator.build(contentSigner),
                kp.getKeypair().getPrivate());

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, params.getPassword());

        ks.setKeyEntry("main", identity.getKey(), params.getPassword(),
                new Certificate[]{identity.getJceCert()});

        ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
        try {
            ks.store(ksStream, params.getPassword());
        } finally {
            ksStream.flush();
        }

        P12KeypairGenerationResult result = new P12KeypairGenerationResult(
                ksStream.toByteArray());
        result.setKeystoreObject(ks);
        return result;
    } // method generateIdentity

    private static ContentSigner getContentSigner(
            final PrivateKey key)
    throws Exception {
        BcContentSignerBuilder builder;

        if (key instanceof RSAPrivateKey) {
            ASN1ObjectIdentifier hashOid = X509ObjectIdentifiers.id_SHA1;
            ASN1ObjectIdentifier sigOid = PKCSObjectIdentifiers.sha1WithRSAEncryption;

            builder = new BcRSAContentSignerBuilder(buildAlgId(sigOid), buildAlgId(hashOid));
        } else if (key instanceof DSAPrivateKey) {
            ASN1ObjectIdentifier hashOid = X509ObjectIdentifiers.id_SHA1;
            AlgorithmIdentifier sigId = new AlgorithmIdentifier(
                    X9ObjectIdentifiers.id_dsa_with_sha1);

            builder = new BcDSAContentSignerBuilder(sigId, buildAlgId(hashOid));
        } else if (key instanceof ECPrivateKey) {
            ASN1ObjectIdentifier hashOid;
            ASN1ObjectIdentifier sigOid;

            int keySize = ((ECPrivateKey) key).getParams().getOrder().bitLength();
            if (keySize > 384) {
                hashOid = NISTObjectIdentifiers.id_sha512;
                sigOid = X9ObjectIdentifiers.ecdsa_with_SHA512;
            } else if (keySize > 256) {
                hashOid = NISTObjectIdentifiers.id_sha384;
                sigOid = X9ObjectIdentifiers.ecdsa_with_SHA384;
            } else if (keySize > 224) {
                hashOid = NISTObjectIdentifiers.id_sha224;
                sigOid = X9ObjectIdentifiers.ecdsa_with_SHA224;
            } else if (keySize > 160) {
                hashOid = NISTObjectIdentifiers.id_sha256;
                sigOid = X9ObjectIdentifiers.ecdsa_with_SHA256;
            } else {
                hashOid = X509ObjectIdentifiers.id_SHA1;
                sigOid = X9ObjectIdentifiers.ecdsa_with_SHA1;
            }

            builder = new ECDSAContentSignerBuilder(new AlgorithmIdentifier(sigOid),
                    buildAlgId(hashOid));
        } else {
            throw new IllegalArgumentException("unknown type of key " + key.getClass().getName());
        }

        return builder.build(KeyUtil.generatePrivateKeyParameter(key));
    } // method getContentSigner

    private static AlgorithmIdentifier buildAlgId(
            final ASN1ObjectIdentifier identifier) {
        return new AlgorithmIdentifier(identifier, DERNull.INSTANCE);
    }

}
