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

package org.xipki.commons.security.p11.sun;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.SignerUtil;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.util.SecurityUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class SunP11Identity implements Comparable<SunP11Identity> {

    private final Cipher rsaCipher;

    private final Signature dsaSignature;

    private final P11SlotIdentifier slotId;

    private final String keyLabel;

    private final PrivateKey privateKey;

    private final X509Certificate[] certificateChain;

    private final PublicKey publicKey;

    private final int signatureKeyBitLength;

    SunP11Identity(
            final Provider p11Provider,
            final P11SlotIdentifier slotId,
            final String keyLabel,
            final PrivateKey privateKey,
            final X509Certificate[] certificateChain,
            final PublicKey publicKey)
    throws SignerException {
        super();

        ParamUtil.assertNotNull("p11Provider", p11Provider);
        ParamUtil.assertNotNull("slotId", slotId);
        ParamUtil.assertNotNull("privateKey", privateKey);
        ParamUtil.assertNotNull("keyLabel", keyLabel);

        if ((certificateChain == null
                || certificateChain.length == 0
                || certificateChain[0] == null)
                && publicKey == null) {
            throw new IllegalArgumentException("neither certificate nor publicKey is non-null");
        }

        this.slotId = slotId;
        this.privateKey = privateKey;
        this.publicKey = (publicKey == null)
                ? certificateChain[0].getPublicKey()
                : publicKey;
        this.certificateChain = certificateChain;

        this.keyLabel = keyLabel;

        if (this.publicKey instanceof RSAPublicKey) {
            signatureKeyBitLength = ((RSAPublicKey) this.publicKey).getModulus().bitLength();
            String algorithm = "RSA/ECB/NoPadding";
            this.dsaSignature = null;
            try {
                this.rsaCipher = Cipher.getInstance(algorithm, p11Provider);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new SignerException(e.getClass().getName() + ": " + e.getMessage(), e);
            }
            try {
                this.rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            } catch (InvalidKeyException e) {
                throw new SignerException("InvalidKeyException: " + e.getMessage(), e);
            }
        } else if (this.publicKey instanceof ECPublicKey
                || this.publicKey instanceof DSAPublicKey) {
            String algorithm;
            if (this.publicKey instanceof ECPublicKey) {
                signatureKeyBitLength = ((ECPublicKey) this.publicKey).getParams().getCurve()
                        .getField().getFieldSize();
                algorithm = "NONEwithECDSA";
            } else if (this.publicKey instanceof DSAPublicKey) {
                signatureKeyBitLength = ((DSAPublicKey) this.publicKey).getParams().getP()
                        .bitLength();
                algorithm = "NONEwithDSA";
            } else {
                throw new RuntimeException("should not reach here");
            }

            try {
                this.dsaSignature = Signature.getInstance(algorithm, p11Provider);
            } catch (NoSuchAlgorithmException e) {
                throw new SignerException("NoSuchAlgorithmException: " + e.getMessage(), e);
            }
            try {
                this.dsaSignature.initSign(privateKey);
            } catch (InvalidKeyException e) {
                throw new SignerException("InvalidKeyException: " + e.getMessage(), e);
            }
            this.rsaCipher = null;
        } else {
            throw new IllegalArgumentException(
                    "currently only RSA, EC and DSA public key are supported, but not "
                    + this.publicKey.getAlgorithm()
                    + " (class: " + this.publicKey.getClass().getName() + ")");
        }
    } // constructor

    public String getKeyLabel() {
        return keyLabel;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate getCertificate() {
        return (certificateChain != null && certificateChain.length > 0)
                ? certificateChain[0]
                : null;
    }

    public X509Certificate[] getCertificateChain() {
        return certificateChain;
    }

    public PublicKey getPublicKey() {
        return (publicKey == null)
                ? certificateChain[0].getPublicKey()
                : publicKey;
    }

    public P11SlotIdentifier getSlotId() {
        return slotId;
    }

    public boolean match(
            final P11SlotIdentifier pSlotId,
            final String pKeyLabel) {
        return this.slotId.equals(pSlotId) && this.keyLabel.equals(pKeyLabel);
    }

    public byte[] CKM_RSA_PKCS(
            final byte[] encodedDigestInfo)
    throws SignerException {
        byte[] padded = SignerUtil.pkcs1padding(encodedDigestInfo,
                (signatureKeyBitLength + 7) / 8);
        return CKM_RSA_X509(padded);
    }

    public byte[] CKM_RSA_X509(
            final byte[] hash)
    throws SignerException {
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new SignerException("operation CKM_RSA_X509 is not allowed for "
                    + publicKey.getAlgorithm() + " public key");
        }

        synchronized (rsaCipher) {
            try {
                rsaCipher.update(hash);
                return rsaCipher.doFinal();
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new SignerException(e.getClass().getName() + ": " + e.getMessage(), e);
            }
        }
    }

    public byte[] CKM_ECDSA(
            final byte[] hash)
    throws SignerException {
        byte[] x962Sig = CKM_ECDSA_X962(hash);
        return SignerUtil.convertX962DSASigToPlain(x962Sig, signatureKeyBitLength);
    }

    public byte[] CKM_ECDSA_X962(
            final byte[] hash)
    throws SignerException {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new SignerException("operation CKM_ECDSA is not allowed for "
                    + publicKey.getAlgorithm() + " public key");
        }

        byte[] truncatedDigest = SecurityUtil.leftmost(hash, signatureKeyBitLength);

        synchronized (dsaSignature) {
            try {
                dsaSignature.update(truncatedDigest);
                return dsaSignature.sign();
            } catch (SignatureException e) {
                throw new SignerException(e.getMessage(), e);
            }
        }
    }

    public byte[] CKM_DSA(
            final byte[] hash)
    throws SignerException {
        byte[] x962Sig = CKM_DSA_X962(hash);
        return SignerUtil.convertX962DSASigToPlain(x962Sig, signatureKeyBitLength);
    }

    public byte[] CKM_DSA_X962(
            final byte[] hash)
    throws SignerException {
        if (!(publicKey instanceof DSAPublicKey)) {
            throw new SignerException("operation CKM_DSA is not allowed for "
                    + publicKey.getAlgorithm() + " public key");
        }

        byte[] truncatedDigest = SecurityUtil.leftmost(hash, signatureKeyBitLength);
        synchronized (dsaSignature) {
            try {
                dsaSignature.update(truncatedDigest);
                return dsaSignature.sign();
            } catch (SignatureException e) {
                throw new SignerException(e.getMessage(), e);
            }
        }
    }

    @Override
    public int compareTo(
            final SunP11Identity o) {
        return this.keyLabel.compareTo(o.keyLabel);
    }

}
