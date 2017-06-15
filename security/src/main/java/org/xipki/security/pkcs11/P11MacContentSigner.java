/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.security.pkcs11;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.operator.ContentSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.XiSecurityException;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */
class P11MacContentSigner implements ContentSigner {

    private static final Logger LOG = LoggerFactory.getLogger(P11MacContentSigner.class);

    private final P11CryptService cryptService;

    private final P11EntityIdentifier identityId;

    private final AlgorithmIdentifier algorithmIdentifier;

    private final long mechanism;

    private final ByteArrayOutputStream outputStream;

    P11MacContentSigner(final P11CryptService cryptService, final P11EntityIdentifier identityId,
            final AlgorithmIdentifier macAlgId)
            throws XiSecurityException, P11TokenException {
        this.identityId = ParamUtil.requireNonNull("identityId", identityId);
        this.cryptService = ParamUtil.requireNonNull("cryptService", cryptService);
        this.algorithmIdentifier = ParamUtil.requireNonNull("macAlgId", macAlgId);

        ASN1ObjectIdentifier oid = macAlgId.getAlgorithm();
        if (PKCSObjectIdentifiers.id_hmacWithSHA1.equals(oid)) {
            mechanism = PKCS11Constants.CKM_SHA_1_HMAC;
        } else if (PKCSObjectIdentifiers.id_hmacWithSHA224.equals(oid)) {
            mechanism = PKCS11Constants.CKM_SHA224_HMAC;
        } else if (PKCSObjectIdentifiers.id_hmacWithSHA256.equals(oid)) {
            mechanism = PKCS11Constants.CKM_SHA256_HMAC;
        } else if (PKCSObjectIdentifiers.id_hmacWithSHA384.equals(oid)) {
            mechanism = PKCS11Constants.CKM_SHA384_HMAC;
        } else if (PKCSObjectIdentifiers.id_hmacWithSHA512.equals(oid)) {
            mechanism = PKCS11Constants.CKM_SHA512_HMAC;
        } else if (NISTObjectIdentifiers.id_hmacWithSHA3_224.equals(oid)) {
            mechanism = PKCS11Constants.CKM_SHA3_224_HMAC;
        } else if (NISTObjectIdentifiers.id_hmacWithSHA3_256.equals(oid)) {
            mechanism = PKCS11Constants.CKM_SHA3_256_HMAC;
        } else if (NISTObjectIdentifiers.id_hmacWithSHA3_384.equals(oid)) {
            mechanism = PKCS11Constants.CKM_SHA3_384_HMAC;
        } else if (NISTObjectIdentifiers.id_hmacWithSHA3_512.equals(oid)) {
            mechanism = PKCS11Constants.CKM_SHA3_512_HMAC;
        } else {
            throw new IllegalArgumentException("unknown algorithm identifier " + oid.getId());
        }

        this.outputStream = new ByteArrayOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        outputStream.reset();
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            byte[] dataToSign = outputStream.toByteArray();
            outputStream.reset();
            return cryptService.getIdentity(identityId).sign(mechanism, null, dataToSign);
        } catch (XiSecurityException ex) {
            LogUtil.warn(LOG, ex);
            throw new RuntimeCryptoException("XiSecurityException: " + ex.getMessage());
        } catch (Throwable th) {
            LogUtil.warn(LOG, th);
            throw new RuntimeCryptoException(th.getClass().getName() + ": " + th.getMessage());
        }
    }

}
