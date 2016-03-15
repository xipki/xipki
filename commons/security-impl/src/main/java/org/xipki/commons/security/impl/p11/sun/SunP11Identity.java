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

package org.xipki.commons.security.impl.p11.sun;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
import org.xipki.commons.security.impl.util.SecurityUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class SunP11Identity extends P11Identity {

    // CHECKSTYLE:OFF
    private static final String RSA_ECB_NoPadding = "RSA/ECB/NoPadding";

    private static final String SHA1withRSA = "SHA1withRSA";

    private static final String SHA224withRSA = "SHA224withRSA";

    private static final String SHA256withRSA = "SHA256withRSA";

    private static final String SHA384withRSA = "SHA384withRSA";

    private static final String SHA512withRSA = "SHA512withRSA";

    private static final String SHA1withDSA = "SHA1withDSA";

    private static final String NONEwithDSA = "NONEwithDSA";

    private static final String SHA1withECDSA = "SHA1withECDSA";

    private static final String NONEwithECDSA = "NONEwithECDSA";
    // CHECKSTYLE:ON

    private final Provider provider;

    private final int maxMessageSize;

    private final PrivateKey privateKey;

    private final Set<String> cipherAlgos = new HashSet<>();

    private final Set<String> sigAlgos = new HashSet<>();

    private final SecureRandom random;

    SunP11Identity(
            final Provider provider,
            final P11EntityIdentifier entityId,
            final int maxMessageSize,
            final PrivateKey privateKey,
            final X509Certificate[] certificateChain,
            final PublicKey publicKey,
            final SecureRandom random)
    throws XiSecurityException {
        super(entityId, certificateChain, publicKey);
        this.provider = ParamUtil.requireNonNull("p11Provider", provider);
        this.maxMessageSize = ParamUtil.requireMin("maxMessageSize", maxMessageSize, 128);
        this.privateKey = ParamUtil.requireNonNull("privateKey", privateKey);
        this.random = ParamUtil.requireNonNull("random", random);

        Set<Service> services = provider.getServices();
        for (Service service : services) {
            String type = service.getType();
            String algo = service.getAlgorithm().toLowerCase();

            if ("Cipher".equalsIgnoreCase(type)) {
                if ("RSA/ECB/NoPadding".equalsIgnoreCase(algo)) {
                    cipherAlgos.add(algo.toLowerCase());
                }
                continue;
            } else if ("Signature".equalsIgnoreCase(type)) {
                sigAlgos.add(algo.toLowerCase());
            }
        }
    } // constructor

    PrivateKey getPrivateKey() {
        return privateKey;
    }

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
            return ecdsaSign(content, null);
        } else if (P11Constants.CKM_ECDSA_SHA1 == mechanism) {
            return ecdsaSign(content, HashAlgoType.SHA1);
        } else if (P11Constants.CKM_DSA == mechanism) {
            return dsaSign(content, null);
        } else if (P11Constants.CKM_DSA_SHA1 == mechanism) {
            return dsaSign(content, HashAlgoType.SHA1);
        } else if (P11Constants.CKM_DSA_SHA224 == mechanism) {
            return dsaSign(content, HashAlgoType.SHA224);
        } else if (P11Constants.CKM_DSA_SHA256 == mechanism) {
            return dsaSign(content, HashAlgoType.SHA256);
        } else if (P11Constants.CKM_DSA_SHA384 == mechanism) {
            return dsaSign(content, HashAlgoType.SHA384);
        } else if (P11Constants.CKM_DSA_SHA512 == mechanism) {
            return dsaSign(content, HashAlgoType.SHA512);
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
        if (cipherAlgos.contains(RSA_ECB_NoPadding)) {
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

        String sigAlgo;
        if (hashAlgo == HashAlgoType.SHA1 && sigAlgos.contains(SHA1withRSA.toLowerCase())) {
            sigAlgo = SHA1withRSA;
        } else if (hashAlgo == HashAlgoType.SHA224
                && sigAlgos.contains(SHA224withRSA.toLowerCase())) {
            sigAlgo = SHA224withRSA;
        } else if (hashAlgo == HashAlgoType.SHA256
                && sigAlgos.contains(SHA256withRSA.toLowerCase())) {
            sigAlgo = SHA256withRSA;
        } else if (hashAlgo == HashAlgoType.SHA384
                && sigAlgos.contains(SHA384withRSA.toLowerCase())) {
            sigAlgo = SHA384withRSA;
        } else if (hashAlgo == HashAlgoType.SHA512
                && sigAlgos.contains(SHA512withRSA.toLowerCase())) {
            sigAlgo = SHA512withRSA;
        } else {
            throw new XiSecurityException(
                    "unsupported signature algorithm RSA_PKCS with " + hashAlgo);
        }

        try {
            Signature sig = Signature.getInstance(sigAlgo, provider);
            updateData(sig, contentToSign);
            return sig.sign();
        } catch (SignatureException | NoSuchAlgorithmException ex) {
            throw new XiSecurityException(ex.getMessage(), ex);
        }
    }

    private byte[] rsaX509Sign(
            final byte[] dataToSign)
    throws XiSecurityException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(RSA_ECB_NoPadding, provider);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new XiSecurityException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        } catch (InvalidKeyException ex) {
            throw new XiSecurityException("InvalidKeyException: " + ex.getMessage(), ex);
        }

        try {
            return cipher.doFinal(dataToSign);
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            throw new XiSecurityException("SignatureException: " + ex.getMessage(), ex);
        }
    }

    private byte[] dsaSign(
            final byte[] dataToSign,
            final HashAlgoType hashAlgo)
    throws XiSecurityException {
        byte[] input;

        String signatureAlgorithm;
        if (sigAlgos.contains(NONEwithDSA.toLowerCase())) {
            byte[] hash;
            if (hashAlgo == null) {
                hash = dataToSign;
            } else {
                hash = HashCalculator.hash(hashAlgo, dataToSign);
            }
            input = SecurityUtil.leftmost(hash, getSignatureKeyBitLength());
            signatureAlgorithm = NONEwithDSA;
        } else if (hashAlgo == HashAlgoType.SHA1 && sigAlgos.contains(SHA1withDSA.toLowerCase())) {
            input = dataToSign;
            signatureAlgorithm = SHA1withDSA;
        } else {
            throw new XiSecurityException("unsupported mechanism");
        }

        try {
            Signature sig = Signature.getInstance(signatureAlgorithm, provider);
            updateData(sig, input);
            byte[] x962Signature = sig.sign();
            return SignerUtil.convertX962DSASigToPlain(x962Signature, getSignatureKeyBitLength());
        } catch (NoSuchAlgorithmException ex) {
            throw new XiSecurityException("could not find signature algorithm " + ex.getMessage(),
                    ex);
        } catch (SignatureException ex) {
            throw new XiSecurityException("SignatureException: " + ex.getMessage(), ex);
        }
    }

    private byte[] ecdsaSign(
            final byte[] dataToSign,
            final HashAlgoType hashAlgo)
    throws XiSecurityException {
        byte[] input;

        String signatureAlgorithm;
        if (sigAlgos.contains(NONEwithECDSA.toLowerCase())) {
            byte[] hash;
            if (hashAlgo == null) {
                hash = dataToSign;
            } else {
                hash = HashCalculator.hash(hashAlgo, dataToSign);
            }
            input = SecurityUtil.leftmost(hash, getSignatureKeyBitLength());
            signatureAlgorithm = NONEwithECDSA;
        } else if (hashAlgo == HashAlgoType.SHA1
                && sigAlgos.contains(SHA1withECDSA.toLowerCase())) {
            input = dataToSign;
            signatureAlgorithm = SHA1withECDSA;
        } else {
            throw new XiSecurityException("unsupported mechanism");
        }

        try {
            Signature sig = Signature.getInstance(signatureAlgorithm, provider);
            updateData(sig, input);
            byte[] x962Signature = sig.sign();
            return SignerUtil.convertX962DSASigToPlain(x962Signature, getSignatureKeyBitLength());
        } catch (NoSuchAlgorithmException ex) {
            throw new XiSecurityException("could not find signature algorithm " + ex.getMessage(),
                    ex);
        } catch (SignatureException ex) {
            throw new XiSecurityException("SignatureException: " + ex.getMessage(), ex);
        }
    }

    private void updateData(
            final Signature sig,
            final byte[] data)
    throws SignatureException {
        final int len = data.length;
        if (len <= maxMessageSize) {
            sig.update(data);
            return;
        }

        for (int i = 0; i < len; i += maxMessageSize) {
            int blockLen = Math.min(maxMessageSize, len - i);
            byte[] block = new byte[blockLen];
            System.arraycopy(data, i, block, 0, blockLen);
            sig.update(block);
        }
    }

}
