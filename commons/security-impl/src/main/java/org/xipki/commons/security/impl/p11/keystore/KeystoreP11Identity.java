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

package org.xipki.commons.security.impl.p11.keystore;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.HashAlgoType;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.XiSecurityException;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.parameters.P11Params;
import org.xipki.commons.security.api.p11.parameters.P11RSAPkcsPssParams;
import org.xipki.commons.security.api.util.SignerUtil;
import org.xipki.commons.security.impl.p12.SoftTokenContentSignerBuilder;
import org.xipki.commons.security.impl.util.SecurityUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class KeystoreP11Identity extends P11Identity {

    private static final Logger LOG = LoggerFactory.getLogger(KeystoreP11Identity.class);

    private final PrivateKey privateKey;

    private final BlockingDeque<Cipher> rsaCiphers = new LinkedBlockingDeque<>();

    private final BlockingDeque<Signature> dsaSignatures = new LinkedBlockingDeque<>();

    private final SecureRandom random;

    public KeystoreP11Identity(
            final P11EntityIdentifier entityId,
            final PrivateKey privateKey,
            final PublicKey publicKey,
            final X509Certificate[] certificateChain,
            final int maxSessions,
            final SecureRandom random)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        super(entityId, certificateChain, publicKey);
        this.privateKey = ParamUtil.requireNonNull("privateKey", privateKey);
        this.random = ParamUtil.requireNonNull("random", random);

        if (this.publicKey instanceof RSAPublicKey) {
            String providerName;
            if (Security.getProvider(SoftTokenContentSignerBuilder.PROVIDER_XIPKI_NSS_CIPHER)
                    != null) {
                providerName = SoftTokenContentSignerBuilder.PROVIDER_XIPKI_NSS_CIPHER;
            } else {
                providerName = "BC";
            }

            LOG.info("use provider {}", providerName);

            for (int i = 0; i < maxSessions; i++) {
                Cipher rsaCipher;
                try {
                    final String algo = "RSA/ECB/NoPadding";
                    rsaCipher = Cipher.getInstance(algo, providerName);
                    LOG.info("use cipher algorithm {}", algo);
                } catch (NoSuchPaddingException ex) {
                    throw new NoSuchAlgorithmException("NoSuchPadding", ex);
                } catch (NoSuchAlgorithmException ex) {
                    final String algo = "RSA/NONE/NoPadding";
                    try {
                        rsaCipher = Cipher.getInstance(algo, providerName);
                        LOG.info("use cipher algorithm {}", algo);
                    } catch (NoSuchPaddingException e1) {
                        throw new NoSuchAlgorithmException("NoSuchPadding", ex);
                    }
                }
                rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
                rsaCiphers.add(rsaCipher);
            }
        } else {
            String algorithm;
            if (this.publicKey instanceof ECPublicKey) {
                algorithm = "NONEwithECDSA";
            } else if (this.publicKey instanceof DSAPublicKey) {
                algorithm = "NONEwithDSA";
            } else {
                throw new IllegalArgumentException(
                        "Currently only RSA, DSA and EC public key are supported, but not "
                        + this.publicKey.getAlgorithm()
                        + " (class: " + this.publicKey.getClass().getName() + ")");
            }

            for (int i = 0; i < maxSessions; i++) {
                Signature dsaSignature = Signature.getInstance(algorithm, "BC");
                dsaSignature.initSign(privateKey, random);
                dsaSignatures.add(dsaSignature);
            }
        }
    } // constructor

    byte[] sign(
            final long mechanism,
            final P11Params parameters,
            final byte[] content)
    throws XiSecurityException {
        ParamUtil.requireNonNull("content", content);

        if (!supportsMechanism(mechanism, parameters)) {
            throw new XiSecurityException("mechanism " + mechanism + " is not allowed for "
                    + publicKey.getAlgorithm() + " public key");
        }

        if (P11Constants.CKM_ECDSA == mechanism) {
            return dsaAndEcdsaSign(content, null);
        } else if (P11Constants.CKM_ECDSA_SHA1 == mechanism) {
            return dsaAndEcdsaSign(content, HashAlgoType.SHA1);
        } else if (P11Constants.CKM_DSA == mechanism) {
            return dsaAndEcdsaSign(content, null);
        } else if (P11Constants.CKM_DSA_SHA1 == mechanism) {
            return dsaAndEcdsaSign(content, HashAlgoType.SHA1);
        } else if (P11Constants.CKM_DSA_SHA224 == mechanism) {
            return dsaAndEcdsaSign(content, HashAlgoType.SHA224);
        } else if (P11Constants.CKM_DSA_SHA256 == mechanism) {
            return dsaAndEcdsaSign(content, HashAlgoType.SHA256);
        } else if (P11Constants.CKM_DSA_SHA384 == mechanism) {
            return dsaAndEcdsaSign(content, HashAlgoType.SHA384);
        } else if (P11Constants.CKM_DSA_SHA512 == mechanism) {
            return dsaAndEcdsaSign(content, HashAlgoType.SHA512);
        } else if (P11Constants.CKM_RSA_X_509 == mechanism) {
            return rsaX509Sign(content);
        } else if (P11Constants.CKM_RSA_PKCS == mechanism) {
            return rsaPkcsSign(content, null);
        } else if (P11Constants.CKM_SHA1_RSA_PKCS == mechanism) {
            return rsaPkcsSign(content, HashAlgoType.SHA1);
        } else if (P11Constants.CKM_SHA224_RSA_PKCS == mechanism) {
            return rsaPkcsSign(content, HashAlgoType.SHA224);
        } else if (P11Constants.CKM_SHA256_RSA_PKCS == mechanism) {
            return rsaPkcsSign(content, HashAlgoType.SHA256);
        } else if (P11Constants.CKM_SHA384_RSA_PKCS == mechanism) {
            return rsaPkcsSign(content, HashAlgoType.SHA384);
        } else if (P11Constants.CKM_SHA512_RSA_PKCS == mechanism) {
            return rsaPkcsSign(content, HashAlgoType.SHA512);
        } else if (P11Constants.CKM_RSA_PKCS_PSS == mechanism) {
            return rsaPkcsPssSign(parameters, content, null);
        } else if (P11Constants.CKM_SHA1_RSA_PKCS_PSS == mechanism) {
            return rsaPkcsPssSign(parameters, content, HashAlgoType.SHA1);
        } else if (P11Constants.CKM_SHA224_RSA_PKCS_PSS == mechanism) {
            return rsaPkcsPssSign(parameters, content, HashAlgoType.SHA224);
        } else if (P11Constants.CKM_SHA256_RSA_PKCS_PSS == mechanism) {
            return rsaPkcsPssSign(parameters, content, HashAlgoType.SHA256);
        } else if (P11Constants.CKM_SHA384_RSA_PKCS_PSS == mechanism) {
            return rsaPkcsPssSign(parameters, content, HashAlgoType.SHA384);
        } else if (P11Constants.CKM_SHA512_RSA_PKCS_PSS == mechanism) {
            return rsaPkcsPssSign(parameters, content, HashAlgoType.SHA512);
        } else {
            throw new XiSecurityException("unsupported mechanism " + mechanism);
        }
    }

    private byte[] rsaPkcsPssSign(
            P11Params parameters,
            final byte[] contentToSign,
            HashAlgoType hashAlgo)
    throws XiSecurityException {
        if (!(parameters instanceof P11RSAPkcsPssParams)) {
            throw new XiSecurityException("the parameters is not of "
                    + P11RSAPkcsPssParams.class.getName());
        }

        P11RSAPkcsPssParams pssParam = (P11RSAPkcsPssParams) parameters;
        HashAlgoType contentHash = HashAlgoType.getInstanceForPkcs11HashMech(
                pssParam.getHashAlgorithm());
        if (contentHash == null) {
            throw new XiSecurityException("unsupported HashAlgorithm " + pssParam.getHashAlgorithm());
        } else if (contentHash != hashAlgo) {
            throw new XiSecurityException("Invalid parameters: invalid hash algorithm");
        }

        HashAlgoType mgfHash = HashAlgoType.getInstanceForPkcs11MgfMech(
                pssParam.getMaskGenerationFunction());
        if (mgfHash == null) {
            throw new XiSecurityException(
                    "unsupported MaskGenerationFunction " + pssParam.getHashAlgorithm());
        }

        byte[] hashValue;
        if (hashAlgo == null) {
            hashValue = contentToSign;
        } else {
            hashValue = HashCalculator.hash(hashAlgo, contentToSign);
        }

        byte[] encodedHashValue = SignerUtil.EMSA_PSS_ENCODE(contentHash, hashValue, mgfHash,
                (int) pssParam.getSaltLength(), getSignatureKeyBitLength(), random);
        return rsaX509Sign(encodedHashValue);
    }

    private byte[] rsaPkcsSign(
            final byte[] contentToSign,
            final HashAlgoType hashAlgo)
    throws XiSecurityException {
        int modulusBitLen = getSignatureKeyBitLength();
        byte[] paddedHash;
        if (hashAlgo == null) {
            paddedHash = SignerUtil.EMSA_PKCS1_v1_5_encoding(contentToSign, modulusBitLen);
        } else {
            byte[] hash = HashCalculator.hash(hashAlgo, contentToSign);
            paddedHash = SignerUtil.EMSA_PKCS1_v1_5_encoding(hash, modulusBitLen, hashAlgo);
        }
        return rsaX509Sign(paddedHash);
    }

    private byte[] rsaX509Sign(
            final byte[] dataToSign)
    throws XiSecurityException {
        Cipher cipher;
        try {
            cipher = rsaCiphers.takeFirst();
        } catch (InterruptedException ex) {
            throw new XiSecurityException(
                    "could not take any idle signer");
        }

        try {
            return cipher.doFinal(dataToSign);
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            throw new XiSecurityException("SignatureException: " + ex.getMessage(), ex);
        } finally {
            rsaCiphers.add(cipher);
        }
    }

    private byte[] dsaAndEcdsaSign(
            final byte[] dataToSign,
            final HashAlgoType hashAlgo)
    throws XiSecurityException {
        byte[] hash;
        if (hashAlgo == null) {
            hash = dataToSign;
        } else {
            hash = HashCalculator.hash(hashAlgo, dataToSign);
        }

        byte[] truncatedDigest = SecurityUtil.leftmost(hash, getSignatureKeyBitLength());
        Signature sig;
        try {
            sig = dsaSignatures.takeFirst();
        } catch (InterruptedException ex) {
            throw new XiSecurityException(
                    "InterruptedException occurs while retrieving idle signature");
        }

        try {
            sig.update(truncatedDigest);
            byte[] x962Signature = sig.sign();
            return SignerUtil.convertX962DSASigToPlain(x962Signature, getSignatureKeyBitLength());
        } catch (SignatureException ex) {
            throw new XiSecurityException("SignatureException: " + ex.getMessage(), ex);
        } finally {
            dsaSignatures.add(sig);
        }
    }

    PrivateKey getPrivateKey() {
        return privateKey;
    }

}
