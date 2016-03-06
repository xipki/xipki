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

package org.xipki.commons.security.impl.p12;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.util.AlgorithmUtil;
import org.xipki.commons.security.api.util.SignerUtil;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.commons.security.impl.DefaultConcurrentContentSigner;
import org.xipki.commons.security.impl.SignatureSigner;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SoftTokenContentSignerBuilder {

    // CHECKSTYLE:SKIP
    private static class RSAContentSignerBuilder extends BcContentSignerBuilder {

        private RSAContentSignerBuilder(
                final AlgorithmIdentifier signatureAlgId)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(signatureAlgId, AlgorithmUtil.extractDigesetAlgorithmIdentifier(signatureAlgId));
        }

        protected Signer createSigner(
                final AlgorithmIdentifier sigAlgId,
                final AlgorithmIdentifier digAlgId)
        throws OperatorCreationException {
            if (!AlgorithmUtil.isRSASignatureAlgoId(sigAlgId)) {
                throw new OperatorCreationException(
                        "the given algorithm is not a valid RSA signature algirthm '"
                        + sigAlgId.getAlgorithm().getId() + "'");
            }

            if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgId.getAlgorithm())) {
                Digest dig = digestProvider.get(digAlgId);
                return new RSADigestSigner(dig);
            }

            if (Security.getProvider(PROVIDER_XIPKI_NSS_CIPHER) == null) {
                return SignerUtil.createPSSRSASigner(sigAlgId);
            }

            NssPlainRSASigner plainSigner;
            try {
                plainSigner = new NssPlainRSASigner();
            } catch (NoSuchAlgorithmException ex) {
                throw new OperatorCreationException(ex.getMessage(), ex);
            } catch (NoSuchProviderException ex) {
                throw new OperatorCreationException(ex.getMessage(), ex);
            } catch (NoSuchPaddingException ex) {
                throw new OperatorCreationException(ex.getMessage(), ex);
            }
            return SignerUtil.createPSSRSASigner(sigAlgId, plainSigner);
        }

    } // class RSAContentSignerBuilder

    // CHECKSTYLE:SKIP
    private static class DSAContentSignerBuilder extends BcContentSignerBuilder {

        private final boolean plain;

        private DSAContentSignerBuilder(
                final AlgorithmIdentifier signatureAlgId,
                final boolean plain)
        throws NoSuchAlgorithmException {
            super(signatureAlgId, AlgorithmUtil.extractDigesetAlgorithmIdentifier(signatureAlgId));
            this.plain = plain;
        }

        protected Signer createSigner(
                final AlgorithmIdentifier sigAlgId,
                final AlgorithmIdentifier digAlgId)
        throws OperatorCreationException {
            if (!AlgorithmUtil.isDSASigAlg(sigAlgId)) {
                throw new OperatorCreationException(
                        "the given algorithm is not a valid DSA signature algirthm '"
                        + sigAlgId.getAlgorithm().getId() + "'");
            }

            Digest dig = digestProvider.get(digAlgId);
            DSASigner dsaSigner = new DSASigner();
            if (plain) {
                return new DSAPlainDigestSigner(dsaSigner, dig);
            } else {
                return new DSADigestSigner(dsaSigner, dig);
            }
        }

    } // class DSAContentSignerBuilder

    // CHECKSTYLE:SKIP
    private static class ECDSAContentSignerBuilder extends BcContentSignerBuilder {

        private final boolean plain;

        private ECDSAContentSignerBuilder(
                final AlgorithmIdentifier signatureAlgId,
                final boolean plain)
        throws NoSuchAlgorithmException {
            super(signatureAlgId, AlgorithmUtil.extractDigesetAlgorithmIdentifier(signatureAlgId));
            this.plain = plain;
        }

        protected Signer createSigner(
                final AlgorithmIdentifier sigAlgId,
                final AlgorithmIdentifier digAlgId)
        throws OperatorCreationException {
            if (!AlgorithmUtil.isECSigAlg(sigAlgId)) {
                throw new OperatorCreationException(
                        "the given algorithm is not a valid EC signature algirthm '"
                        + sigAlgId.getAlgorithm().getId() + "'");
            }

            Digest dig = digestProvider.get(digAlgId);
            ECDSASigner dsaSigner = new ECDSASigner();

            if (plain) {
                return new DSAPlainDigestSigner(dsaSigner, dig);
            } else {
                return new DSADigestSigner(dsaSigner, dig);
            }
        }

    } // class ECDSAContentSignerBuilder

    public static final String PROVIDER_XIPKI_NSS = "XipkiNSS";

    public static final String PROVIDER_XIPKI_NSS_CIPHER = "SunPKCS11-XipkiNSS";

    private static final Logger LOG = LoggerFactory.getLogger(SoftTokenContentSignerBuilder.class);

    private final PrivateKey key;

    private final PublicKey publicKey;

    private final X509Certificate[] certificateChain;

    public SoftTokenContentSignerBuilder(
            final PrivateKey privateKey,
            final PublicKey publicKey)
    throws SignerException {
        this.key = ParamUtil.requireNonNull("privateKey", privateKey);
        this.publicKey = ParamUtil.requireNonNull("publicKey", publicKey);
        this.certificateChain = null;
    }

    public SoftTokenContentSignerBuilder(
            final String keystoreType,
            final InputStream keystoreStream,
            final char[] keystorePassword,
            final String keyname,
            final char[] keyPassword,
            final X509Certificate[] certificateChain)
    throws SignerException {
        if (!("PKCS12".equalsIgnoreCase(keystoreType) || "JKS".equalsIgnoreCase(keystoreType))) {
            throw new IllegalArgumentException("unsupported keystore type: " + keystoreType);
        }
        ParamUtil.requireNonNull("keystoreStream", keystoreStream);
        ParamUtil.requireNonNull("keystorePassword", keystorePassword);
        ParamUtil.requireNonNull("keyPassword", keyPassword);

        try {
            KeyStore ks;
            if ("JKS".equalsIgnoreCase(keystoreType)) {
                ks = KeyStore.getInstance(keystoreType);
            } else {
                ks = KeyStore.getInstance(keystoreType, "BC");
            }
            ks.load(keystoreStream, keystorePassword);

            String tmpKeyname = keyname;
            if (tmpKeyname == null) {
                Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (ks.isKeyEntry(alias)) {
                        tmpKeyname = alias;
                        break;
                    }
                }
            } else {
                if (!ks.isKeyEntry(tmpKeyname)) {
                    throw new SignerException("unknown key named " + tmpKeyname);
                }
            }

            this.key = (PrivateKey) ks.getKey(tmpKeyname, keyPassword);

            if (!(key instanceof RSAPrivateKey || key instanceof DSAPrivateKey
                    || key instanceof ECPrivateKey)) {
                throw new SignerException("unsupported key " + key.getClass().getName());
            }

            Set<Certificate> caCerts = new HashSet<>();

            X509Certificate cert;
            final int n = (certificateChain == null)
                    ? 0
                    : certificateChain.length;
            if (n > 0) {
                cert = certificateChain[0];
                if (n > 1) {
                    for (int i = 1; i < n; i++) {
                        caCerts.add(certificateChain[i]);
                    }
                }
            } else {
                cert = (X509Certificate) ks.getCertificate(tmpKeyname);
            }

            Certificate[] certsInKeystore = ks.getCertificateChain(tmpKeyname);
            if (certsInKeystore.length > 1) {
                for (int i = 1; i < certsInKeystore.length; i++) {
                    caCerts.add(certsInKeystore[i]);
                }
            }

            this.publicKey = cert.getPublicKey();
            this.certificateChain = X509Util.buildCertPath(cert, caCerts);
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException
                | CertificateException | IOException | UnrecoverableKeyException
                | ClassCastException ex) {
            throw new SignerException(ex.getMessage(), ex);
        }
    }

    public ConcurrentContentSigner createSigner(
            final AlgorithmIdentifier signatureAlgId,
            final int parallelism,
            final SecureRandom random)
    throws OperatorCreationException, NoSuchPaddingException {
        ParamUtil.requireNonNull("signatureAlgId", signatureAlgId);
        ParamUtil.requireMin("parallelism", parallelism, 1);

        List<ContentSigner> signers = new ArrayList<>(parallelism);

        ASN1ObjectIdentifier algOid = signatureAlgId.getAlgorithm();

        if (Security.getProvider(PROVIDER_XIPKI_NSS) != null
                && !algOid.equals(PKCSObjectIdentifiers.id_RSASSA_PSS)
                && !(key instanceof ECPrivateKey)) {
            String algoName;
            try {
                algoName = AlgorithmUtil.getSignatureAlgoName(signatureAlgId);
            } catch (NoSuchAlgorithmException ex) {
                throw new OperatorCreationException(ex.getMessage());
            }

            boolean useGivenProvider = true;
            for (int i = 0; i < parallelism; i++) {
                try {
                    Signature signature = Signature.getInstance(algoName, PROVIDER_XIPKI_NSS);
                    signature.initSign(key);
                    if (i == 0) {
                        signature.update(new byte[]{1, 2, 3, 4});
                        signature.sign();
                    }
                    ContentSigner signer = new SignatureSigner(signatureAlgId, signature, key);
                    signers.add(signer);
                } catch (Exception ex) {
                    useGivenProvider = false;
                    signers.clear();
                    break;
                }
            }

            if (useGivenProvider) {
                LOG.info("use {} to sign {} signature", PROVIDER_XIPKI_NSS, algoName);
            } else {
                LOG.info("could not use {} to sign {} signature", PROVIDER_XIPKI_NSS, algoName);
            }
        }

        if (CollectionUtil.isEmpty(signers)) {
            BcContentSignerBuilder signerBuilder;
            AsymmetricKeyParameter keyparam;
            try {
                if (key instanceof RSAPrivateKey) {
                    keyparam = SignerUtil.generateRSAPrivateKeyParameter((RSAPrivateKey) key);
                    signerBuilder = new RSAContentSignerBuilder(signatureAlgId);
                } else if (key instanceof DSAPrivateKey) {
                    keyparam = DSAUtil.generatePrivateKeyParameter(key);
                    signerBuilder = new DSAContentSignerBuilder(signatureAlgId,
                            AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId));
                } else if (key instanceof ECPrivateKey) {
                    keyparam = ECUtil.generatePrivateKeyParameter(key);
                    signerBuilder = new ECDSAContentSignerBuilder(signatureAlgId,
                            AlgorithmUtil.isDSAPlainSigAlg(signatureAlgId));
                } else {
                    throw new OperatorCreationException("unsupported key "
                            + key.getClass().getName());
                }
            } catch (InvalidKeyException ex) {
                throw new OperatorCreationException("invalid key", ex);
            } catch (NoSuchAlgorithmException ex) {
                throw new OperatorCreationException("no such algorithm", ex);
            }

            for (int i = 0; i < parallelism; i++) {
                if (random != null) {
                    signerBuilder.setSecureRandom(random);
                }

                ContentSigner signer = signerBuilder.build(keyparam);
                signers.add(signer);
            }
        }

        ConcurrentContentSigner concurrentSigner = new DefaultConcurrentContentSigner(signers, key);
        if (certificateChain != null) {
            concurrentSigner.setCertificateChain(certificateChain);
        } else {
            concurrentSigner.setPublicKey(publicKey);
        }
        return concurrentSigner;
    } // createSigner

    public X509Certificate getCert() {
        if (certificateChain != null && certificateChain.length > 0) {
            return certificateChain[0];
        } else {
            return null;
        }
    }

    public X509Certificate[] getCertificateChain() {
        return certificateChain;
    }

    public PrivateKey getKey() {
        return key;
    }

}
