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

package org.xipki.commons.security.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.security.api.AbstractSecurityFactory;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.KeyCertPair;
import org.xipki.commons.security.api.NoIdleSignerException;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.SignatureAlgoControl;
import org.xipki.commons.security.api.SignerFactoryRegister;
import org.xipki.commons.security.api.util.AlgorithmUtil;
import org.xipki.commons.security.api.util.KeyUtil;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SecurityFactoryImpl extends AbstractSecurityFactory {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityFactoryImpl.class);

    private static final DefaultDigestAlgorithmIdentifierFinder DFLT_DIGESTALG_IDENTIFIER_FINDER =
            new DefaultDigestAlgorithmIdentifierFinder();

    private static final Map<String, BcContentVerifierProviderBuilder> VERIFIER_PROVIDER_BUILDER
        = new HashMap<>();

    private int defaultSignerParallelism = 32;

    private PasswordResolver passwordResolver;

    private SignerFactoryRegister signerFactoryRegister;

    private long newSignerTimeout;

    private boolean strongRandom4KeyEnabled = true;

    private boolean strongRandom4SignEnabled;

    public SecurityFactoryImpl() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public boolean isStrongRandom4KeyEnabled() {
        return strongRandom4KeyEnabled;
    }

    public void setStrongRandom4KeyEnabled(
            final boolean strongRandom4KeyEnabled) {
        this.strongRandom4KeyEnabled = strongRandom4KeyEnabled;
    }

    public boolean isStrongRandom4SignEnabled() {
        return strongRandom4SignEnabled;
    }

    public void setStrongRandom4SignEnabled(
            final boolean strongRandom4SignEnabled) {
        this.strongRandom4SignEnabled = strongRandom4SignEnabled;
    }

    @Override
    public ConcurrentContentSigner createSigner(
            final String type,
            final String confWithoutAlgo,
            final String hashAlgo,
            final SignatureAlgoControl sigAlgoControl,
            final X509Certificate[] certs)
    throws SecurityException {
        ConcurrentContentSigner signer = signerFactoryRegister.newSigner(type, confWithoutAlgo,
                hashAlgo, sigAlgoControl, certs, newSignerTimeout);
        validateSigner(signer, type, confWithoutAlgo);
        return signer;
    }

    @Override
    public ConcurrentContentSigner createSigner(
            final String type,
            final String conf,
            final X509Certificate[] certificateChain)
    throws SecurityException {
        ConcurrentContentSigner signer = signerFactoryRegister.newSigner(type, conf, null, null,
                certificateChain, newSignerTimeout);
        validateSigner(signer, type, conf);
        return signer;
    }

    @Override
    public ContentVerifierProvider getContentVerifierProvider(
            final PublicKey publicKey)
    throws InvalidKeyException {
        ParamUtil.requireNonNull("publicKey", publicKey);

        String keyAlg = publicKey.getAlgorithm().toUpperCase();
        if ("EC".equals(keyAlg)) {
            keyAlg = "ECDSA";
        }

        BcContentVerifierProviderBuilder builder = VERIFIER_PROVIDER_BUILDER.get(keyAlg);
        if (builder == null) {
            if ("RSA".equals(keyAlg)) {
                builder = new BcRSAContentVerifierProviderBuilder(DFLT_DIGESTALG_IDENTIFIER_FINDER);
            } else if ("DSA".equals(keyAlg)) {
                builder = new BcDSAContentVerifierProviderBuilder(DFLT_DIGESTALG_IDENTIFIER_FINDER);
            } else if ("ECDSA".equals(keyAlg)) {
                builder = new BcECContentVerifierProviderBuilder(DFLT_DIGESTALG_IDENTIFIER_FINDER);
            } else {
                throw new InvalidKeyException("unknown key algorithm of the public key "
                        + keyAlg);
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
    public PublicKey generatePublicKey(
            final SubjectPublicKeyInfo subjectPublicKeyInfo)
    throws InvalidKeyException {
        try {
            return KeyUtil.generatePublicKey(subjectPublicKeyInfo);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new InvalidKeyException(ex.getMessage(), ex);
        }
    }

    @Override
    public boolean verifyPopo(
            final CertificationRequest p10Req) {
        return verifyPopo(new PKCS10CertificationRequest(p10Req));
    }

    @Override
    public boolean verifyPopo(
            final PKCS10CertificationRequest p10Request) {
        try {
            SubjectPublicKeyInfo pkInfo = p10Request.getSubjectPublicKeyInfo();
            PublicKey pk = KeyUtil.generatePublicKey(pkInfo);

            ContentVerifierProvider cvp = getContentVerifierProvider(pk);
            return p10Request.isSignatureValid(cvp);
        } catch (InvalidKeyException | PKCSException | NoSuchAlgorithmException
                | InvalidKeySpecException ex) {
            String message = "could not validate POPO of PKCS#10 request";
            LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
            LOG.error(message, ex);
            return false;
        }
    }

    @Override
    public int getDefaultSignerParallelism() {
        return defaultSignerParallelism;
    }

    public void setDefaultSignerParallelism(
            final int defaultSignerParallelism) {
        this.defaultSignerParallelism = ParamUtil.requireMin("defaultSignerParallelism",
                defaultSignerParallelism, 1);
    }

    public void setNewSignerTimeout(
            final long newSignerTimeout) {
        this.newSignerTimeout = ParamUtil.requireMin("newSignerTimeout", newSignerTimeout, 0);
    }

    public void setSignerFactoryRegister(
            final SignerFactoryRegister signerFactoryRegister) {
        this.signerFactoryRegister = signerFactoryRegister;
    }

    public void setPasswordResolver(
            final PasswordResolver passwordResolver) {
        this.passwordResolver = passwordResolver;
    }

    @Override
    public PasswordResolver getPasswordResolver() {
        return passwordResolver;
    }

    @Override
    public KeyCertPair createPrivateKeyAndCert(
            final String type,
            final String conf,
            final X509Certificate cert)
    throws SecurityException {
        ConfPairs confPairs = new ConfPairs(conf);
        confPairs.putPair("parallelism", Integer.toString(1));
        String algo = confPairs.getValue("algo");

        X509Certificate[] certs = null;
        if (cert != null) {
            certs = new X509Certificate[]{cert};
        }
        ConcurrentContentSigner signer;
        if (algo == null) {
            signer = signerFactoryRegister.newSigner(type, confPairs.getEncoded(), "SHA256",
                    new SignatureAlgoControl(), certs, newSignerTimeout);
        } else {
            signer = signerFactoryRegister.newSigner(type, confPairs.getEncoded(), certs,
                    newSignerTimeout);
        }
        return new KeyCertPair(signer.getPrivateKey(), signer.getCertificate());
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
    public byte[] extractMinimalKeyStore(
            final String keystoreType,
            final byte[] keystoreBytes,
            final String keyname,
            final char[] password,
            final X509Certificate[] newCertChain)
    throws KeyStoreException {
        ParamUtil.requireNonBlank("keystoreType", keystoreType);
        ParamUtil.requireNonNull("keystoreBytes", keystoreBytes);

        try {
            KeyStore ks;
            if ("JKS".equalsIgnoreCase(keystoreType)) {
                ks = KeyStore.getInstance(keystoreType);
            } else {
                ks = KeyStore.getInstance(keystoreType, "BC");
            }
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

            Certificate[] certs;
            if (newCertChain == null || newCertChain.length < 1) {
                if (numAliases == 1) {
                    return keystoreBytes;
                }
                certs = ks.getCertificateChain(tmpKeyname);
            } else {
                certs = newCertChain;
            }

            KeyStore newKs;
            if ("JKS".equalsIgnoreCase(keystoreType)) {
                newKs = KeyStore.getInstance(keystoreType);
            } else {
                newKs = KeyStore.getInstance(keystoreType, "BC");
            }
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

    private static SecureRandom getSecureRandom(
            final boolean strong) {
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

    private static void validateSigner(
            final ConcurrentContentSigner signer,
            final String signerType,
            final String signerConf)
    throws SecurityException {
        if (signer.getPublicKey() == null) {
            return;
        }

        String signatureAlgoName;
        try {
            signatureAlgoName = AlgorithmUtil.getSignatureAlgoName(
                    signer.getAlgorithmIdentifier());
        } catch (NoSuchAlgorithmException ex) {
            throw new SecurityException(ex.getMessage(), ex);
        }

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
                ConfPairs keyValues = new ConfPairs(signerConf);
                String pwd = keyValues.getValue("password");
                if (pwd != null) {
                    keyValues.putPair("password", "****");
                }
                keyValues.putPair("algo", signatureAlgoName);
                sb.append("conf='").append(keyValues.getEncoded());
                X509Certificate cert = signer.getCertificate();
                if (cert != null) {
                    String subject = X509Util.getRfc4519Name(cert.getSubjectX500Principal());
                    sb.append("', certificate subject='").append(subject).append("'");
                }

                throw new SecurityException(sb.toString());
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException
                | SignatureException | NoSuchProviderException | NoIdleSignerException ex) {
            throw new SecurityException(ex.getMessage(), ex);
        }
    } // method validateSigner

}
