/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.password.PasswordResolver;
import org.xipki.security.bc.XiECContentVerifierProviderBuilder;
import org.xipki.security.bc.XiRSAContentVerifierProviderBuilder;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SecurityFactoryImpl extends AbstractSecurityFactory {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityFactoryImpl.class);

    private static final DigestAlgorithmIdentifierFinder DIGESTALG_IDENTIFIER_FINDER =
            new DefaultDigestAlgorithmIdentifierFinder();

    private static final Map<String, BcContentVerifierProviderBuilder> VERIFIER_PROVIDER_BUILDER
        = new HashMap<>();

    private int defaultSignerParallelism = 32;

    private PasswordResolver passwordResolver;

    private SignerFactoryRegister signerFactoryRegister;

    private boolean strongRandom4KeyEnabled;

    private boolean strongRandom4SignEnabled;

    public SecurityFactoryImpl() {
    }

    public boolean isStrongRandom4KeyEnabled() {
        return strongRandom4KeyEnabled;
    }

    public void setStrongRandom4KeyEnabled(final boolean strongRandom4KeyEnabled) {
        this.strongRandom4KeyEnabled = strongRandom4KeyEnabled;
    }

    public boolean isStrongRandom4SignEnabled() {
        return strongRandom4SignEnabled;
    }

    public void setStrongRandom4SignEnabled(final boolean strongRandom4SignEnabled) {
        this.strongRandom4SignEnabled = strongRandom4SignEnabled;
    }

    @Override
    public ConcurrentContentSigner createSigner(final String type, final SignerConf conf,
            final X509Certificate[] certificateChain) throws ObjectCreationException {
        ConcurrentContentSigner signer = signerFactoryRegister.newSigner(this, type, conf,
                certificateChain);
        if (!signer.isMac()) {
            validateSigner(signer, type, conf);
        }
        return signer;
    }

    @Override
    public ContentVerifierProvider getContentVerifierProvider(final PublicKey publicKey)
            throws InvalidKeyException {
        ParamUtil.requireNonNull("publicKey", publicKey);

        String keyAlg = publicKey.getAlgorithm().toUpperCase();

        BcContentVerifierProviderBuilder builder = VERIFIER_PROVIDER_BUILDER.get(keyAlg);
        if (builder == null) {
            if ("RSA".equals(keyAlg)) {
                builder = new XiRSAContentVerifierProviderBuilder(DIGESTALG_IDENTIFIER_FINDER);
            } else if ("DSA".equals(keyAlg)) {
                builder = new BcDSAContentVerifierProviderBuilder(DIGESTALG_IDENTIFIER_FINDER);
            } else if ("EC".equals(keyAlg) || "ECDSA".equals(keyAlg)) {
                builder = new XiECContentVerifierProviderBuilder(DIGESTALG_IDENTIFIER_FINDER);
            } else {
                throw new InvalidKeyException("unknown key algorithm of the public key " + keyAlg);
            }
            VERIFIER_PROVIDER_BUILDER.put(keyAlg, builder);
        }

        AsymmetricKeyParameter keyParam = KeyUtil.generatePublicKeyParameter(publicKey);
        try {
            return builder.build(keyParam);
        } catch (OperatorCreationException ex) {
            throw new InvalidKeyException("could not build ContentVerifierProvider: "
                    + ex.getMessage(), ex);
        }
    }

    @Override
    public PublicKey generatePublicKey(final SubjectPublicKeyInfo subjectPublicKeyInfo)
            throws InvalidKeyException {
        try {
            return KeyUtil.generatePublicKey(subjectPublicKeyInfo);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new InvalidKeyException(ex.getMessage(), ex);
        }
    }

    @Override
    public boolean verifyPopo(final CertificationRequest csr,
            final AlgorithmValidator algoValidator) {
        return verifyPopo(new PKCS10CertificationRequest(csr), algoValidator);
    }

    @Override
    public boolean verifyPopo(final PKCS10CertificationRequest csr,
            final AlgorithmValidator algoValidator) {
        if (algoValidator != null) {
            AlgorithmIdentifier algId = csr.getSignatureAlgorithm();
            if (!algoValidator.isAlgorithmPermitted(algId)) {
                String algoName;
                try {
                    algoName = AlgorithmUtil.getSignatureAlgoName(algId);
                } catch (NoSuchAlgorithmException ex) {
                    algoName = algId.getAlgorithm().getId();
                }

                LOG.error("POPO signature algorithm {} not permitted", algoName);
                return false;
            }
        }

        try {
            SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
            PublicKey pk = KeyUtil.generatePublicKey(pkInfo);
            ContentVerifierProvider cvp = getContentVerifierProvider(pk);
            return csr.isSignatureValid(cvp);
        } catch (InvalidKeyException | PKCSException | NoSuchAlgorithmException
                | InvalidKeySpecException ex) {
            LogUtil.error(LOG, ex, "could not validate POPO of CSR");
            return false;
        }
    }

    @Override
    public int getDefaultSignerParallelism() {
        return defaultSignerParallelism;
    }

    public void setDefaultSignerParallelism(final int defaultSignerParallelism) {
        this.defaultSignerParallelism = ParamUtil.requireMin("defaultSignerParallelism",
                defaultSignerParallelism, 1);
    }

    public void setSignerFactoryRegister(final SignerFactoryRegister signerFactoryRegister) {
        this.signerFactoryRegister = signerFactoryRegister;
    }

    public void setPasswordResolver(final PasswordResolver passwordResolver) {
        this.passwordResolver = passwordResolver;
    }

    @Override
    public PasswordResolver getPasswordResolver() {
        return passwordResolver;
    }

    @Override
    public KeyCertPair createPrivateKeyAndCert(final String type, final SignerConf conf,
            final X509Certificate cert) throws ObjectCreationException {
        conf.putConfEntry("parallelism", Integer.toString(1));

        X509Certificate[] certs = null;
        if (cert != null) {
            certs = new X509Certificate[]{cert};
        }

        ConcurrentContentSigner signer = signerFactoryRegister.newSigner(this, type, conf, certs);
        PrivateKey privateKey = (PrivateKey) signer.getSigningKey();
        return new KeyCertPair(privateKey, signer.getCertificate());
    }

    @Override
    public SecureRandom getRandom4Key() {
        return getSecureRandom(strongRandom4KeyEnabled);
    }

    @Override
    public SecureRandom getRandom4Sign() {
        return getSecureRandom(strongRandom4SignEnabled);
    }

    @Override
    public byte[] extractMinimalKeyStore(final String keystoreType, final byte[] keystoreBytes,
            final String keyname, final char[] password, final X509Certificate[] newCertChain)
            throws KeyStoreException {
        ParamUtil.requireNonBlank("keystoreType", keystoreType);
        ParamUtil.requireNonNull("keystoreBytes", keystoreBytes);

        try {
            KeyStore ks = KeyUtil.getKeyStore(keystoreType);
            ks.load(new ByteArrayInputStream(keystoreBytes), password);

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
                    throw new KeyStoreException("unknown key named " + tmpKeyname);
                }
            }

            Enumeration<String> aliases = ks.aliases();
            int numAliases = 0;
            while (aliases.hasMoreElements()) {
                aliases.nextElement();
                numAliases++;
            }

            if (tmpKeyname == null) {
                throw new KeyStoreException("no key entry is contained in the keystore");
            }

            Certificate[] certs;
            if (newCertChain == null || newCertChain.length < 1) {
                if (numAliases == 1) {
                    return keystoreBytes;
                }
                certs = ks.getCertificateChain(tmpKeyname);
            } else {
                certs = newCertChain;
            }

            KeyStore newKs = KeyUtil.getKeyStore(keystoreType);
            newKs.load(null, password);

            PrivateKey key = (PrivateKey) ks.getKey(tmpKeyname, password);
            newKs.setKeyEntry(tmpKeyname, key, password, certs);
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            newKs.store(bout, password);
            byte[] bytes = bout.toByteArray();
            bout.close();
            return bytes;
        } catch (Exception ex) {
            if (ex instanceof KeyStoreException) {
                throw (KeyStoreException) ex;
            } else {
                throw new KeyStoreException(ex.getMessage(), ex);
            }
        }
    } // method extractMinimalKeyStore

    private static SecureRandom getSecureRandom(final boolean strong) {
        if (!strong) {
            return new SecureRandom();
        }

        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeCryptoException(
                    "could not get strong SecureRandom: " + ex.getMessage());
        }
    }

    private static void validateSigner(final ConcurrentContentSigner signer,
            final String signerType, final SignerConf signerConf) throws ObjectCreationException {
        if (signer.getPublicKey() == null) {
            return;
        }

        String signatureAlgoName = signer.getAlgorithmName();

        try {
            byte[] dummyContent = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
            Signature verifier = Signature.getInstance(signatureAlgoName, "BC");

            byte[] signatureValue = signer.sign(dummyContent);

            verifier.initVerify(signer.getPublicKey());
            verifier.update(dummyContent);
            boolean valid = verifier.verify(signatureValue);
            if (!valid) {
                StringBuilder sb = new StringBuilder();
                sb.append("private key and public key does not match, ");
                sb.append("key type='").append(signerType).append("'; ");
                String pwd = signerConf.getConfValue("password");
                if (pwd != null) {
                    signerConf.putConfEntry("password", "****");
                }
                signerConf.putConfEntry("algo", signatureAlgoName);
                sb.append("conf='").append(signerConf.getConf());
                X509Certificate cert = signer.getCertificate();
                if (cert != null) {
                    String subject = X509Util.getRfc4519Name(cert.getSubjectX500Principal());
                    sb.append("', certificate subject='").append(subject).append("'");
                }

                throw new ObjectCreationException(sb.toString());
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException
                | SignatureException | NoSuchProviderException | NoIdleSignerException ex) {
            throw new ObjectCreationException(ex.getMessage(), ex);
        }
    } // method validateSigner

}
