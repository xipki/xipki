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

package org.xipki.commons.security.api.p11;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.p11.parameters.P11Params;
import org.xipki.commons.security.api.p11.parameters.P11RSAPkcsPssParams;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11Identity implements Comparable<P11Identity> {

    private static final Logger LOG = LoggerFactory.getLogger(P11Identity.class);

    protected final P11Slot slot;

    protected final P11EntityIdentifier identityId;

    protected final PublicKey publicKey;

    private final int signatureKeyBitLength;

    protected X509Certificate[] certificateChain;

    public P11Identity(
            final P11Slot slot,
            final P11EntityIdentifier identityId,
            final PublicKey publicKey,
            final X509Certificate[] certificateChain) {
        this.slot = ParamUtil.requireNonNull("slot", slot);
        this.identityId = ParamUtil.requireNonNull("identityId", identityId);
        if ((certificateChain == null || certificateChain.length < 1 || certificateChain[0] == null)
                && publicKey == null) {
            throw new IllegalArgumentException("neither certificate nor publicKey is non-null");
        }

        this.certificateChain =
                (certificateChain != null && certificateChain.length > 0)
                        ? certificateChain
                        : null;

        this.publicKey = (publicKey == null)
                ? certificateChain[0].getPublicKey()
                : publicKey;

        if (this.publicKey instanceof RSAPublicKey) {
            signatureKeyBitLength = ((RSAPublicKey) this.publicKey).getModulus().bitLength();
        } else if (this.publicKey instanceof ECPublicKey) {
            signatureKeyBitLength = ((ECPublicKey) this.publicKey)
                    .getParams().getCurve().getField().getFieldSize();
        } else if (this.publicKey instanceof DSAPublicKey) {
            signatureKeyBitLength = ((DSAPublicKey) this.publicKey).getParams().getQ().bitLength();
        } else {
            throw new IllegalArgumentException(
                    "currently only RSA, DSA and EC public key are supported, but not "
                    + this.publicKey.getAlgorithm()
                    + " (class: " + this.publicKey.getClass().getName() + ")");
        }
    } // constructor

    public byte[] sign(
            final long mechanism,
            final P11Params parameters,
            final byte[] content)
    throws P11TokenException, SecurityException {
        ParamUtil.requireNonNull("content", content);
        slot.assertMechanismSupported(mechanism);
        if (!supportsMechanism(mechanism, parameters)) {
            throw new P11UnsupportedMechanismException(mechanism, identityId);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("sign with mechanism {}", P11Constants.getMechanismDesc(mechanism));
        }
        return doSign(mechanism, parameters, content);
    }

    protected abstract byte[] doSign(
            final long mechanism,
            @Nullable final P11Params parameters,
            @Nonnull final byte[] content)
    throws P11TokenException, SecurityException;

    public P11EntityIdentifier getIdentityId() {
        return identityId;
    }

    public X509Certificate getCertificate() {
        return (certificateChain != null && certificateChain.length > 0)
                ? certificateChain[0]
                : null;
    }

    public X509Certificate[] getCertificateChain() {
        return (certificateChain == null)
                ? null
                : java.util.Arrays.copyOf(certificateChain, certificateChain.length);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setCertificates(
            X509Certificate[] certificateChain)
    throws P11TokenException {
        if (certificateChain == null || certificateChain.length == 0) {
            this.certificateChain = null;
        } else {
            PublicKey pk = certificateChain[0].getPublicKey();
            if (!this.publicKey.equals(pk)) {
                throw new P11TokenException("certificateChain is not for the key");
            }
            this.certificateChain = certificateChain;
        }
    }

    public boolean match(
            final P11EntityIdentifier identityId) {
        return this.identityId.equals(identityId);
    }

    public boolean match(
            final P11SlotIdentifier slotId,
            final String keyLabel) {
        return identityId.match(slotId, keyLabel);
    }

    public int getSignatureKeyBitLength() {
        return signatureKeyBitLength;
    }

    @Override
    public int compareTo(P11Identity obj) {
        return identityId.compareTo(obj.identityId);
    }

    public boolean supportsMechanism(
            final long mechanism,
            final P11Params parameters) {
        if (publicKey instanceof RSAPublicKey) {
            if (P11Constants.CKM_RSA_9796 == mechanism
                    || P11Constants.CKM_RSA_PKCS == mechanism
                    || P11Constants.CKM_SHA1_RSA_PKCS == mechanism
                    || P11Constants.CKM_SHA224_RSA_PKCS == mechanism
                    || P11Constants.CKM_SHA256_RSA_PKCS == mechanism
                    || P11Constants.CKM_SHA384_RSA_PKCS == mechanism
                    || P11Constants.CKM_SHA512_RSA_PKCS == mechanism) {
                return parameters == null;
            } else if (P11Constants.CKM_RSA_PKCS_PSS == mechanism
                    || P11Constants.CKM_SHA1_RSA_PKCS_PSS == mechanism
                    || P11Constants.CKM_SHA224_RSA_PKCS_PSS == mechanism
                    || P11Constants.CKM_SHA256_RSA_PKCS_PSS == mechanism
                    || P11Constants.CKM_SHA384_RSA_PKCS_PSS == mechanism
                    || P11Constants.CKM_SHA512_RSA_PKCS_PSS == mechanism) {
                return parameters instanceof P11RSAPkcsPssParams;
            } else if (P11Constants.CKM_RSA_X_509 == mechanism) {
            	return true;
            }
        } else if (publicKey instanceof DSAPublicKey) {
            if (parameters != null) {
                return false;
            }
            if (P11Constants.CKM_DSA == mechanism
                    || P11Constants.CKM_DSA_SHA1 == mechanism
                    || P11Constants.CKM_DSA_SHA224 == mechanism
                    || P11Constants.CKM_DSA_SHA256 == mechanism
                    || P11Constants.CKM_DSA_SHA384 == mechanism
                    || P11Constants.CKM_DSA_SHA512 == mechanism) {
                return true;
            }
        } else if (publicKey instanceof ECPublicKey) {
            if (parameters != null) {
                return false;
            }
            if (P11Constants.CKM_ECDSA == mechanism
                    || P11Constants.CKM_ECDSA_SHA1 == mechanism
                    || P11Constants.CKM_ECDSA_SHA224 == mechanism
                    || P11Constants.CKM_ECDSA_SHA256 == mechanism
                    || P11Constants.CKM_ECDSA_SHA384 == mechanism
                    || P11Constants.CKM_ECDSA_SHA512 == mechanism) {
                return true;
            }
        }

        return false;
    }

}
