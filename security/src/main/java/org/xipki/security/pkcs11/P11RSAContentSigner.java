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
import java.io.IOException;
import java.io.OutputStream;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.HashAlgoType;
import org.xipki.security.bc.XiContentSigner;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.SignerUtil;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
//CHECKSTYLE:SKIP
class P11RSAContentSigner implements XiContentSigner {

    private static final Logger LOG = LoggerFactory.getLogger(P11RSAContentSigner.class);

    private final AlgorithmIdentifier algorithmIdentifier;

    private final byte[] encodedAlgorithmIdentifier;

    private final long mechanism;

    private final OutputStream outputStream;

    private final P11CryptService cryptService;

    private final P11EntityIdentifier identityId;

    private final byte[] digestPkcsPrefix;

    private final int modulusBitLen;

    P11RSAContentSigner(final P11CryptService cryptService, final P11EntityIdentifier identityId,
            final AlgorithmIdentifier signatureAlgId)
            throws XiSecurityException, P11TokenException {
        this.cryptService = ParamUtil.requireNonNull("cryptService", cryptService);
        this.identityId = ParamUtil.requireNonNull("identityId", identityId);
        this.algorithmIdentifier = ParamUtil.requireNonNull("signatureAlgId", signatureAlgId);
        try {
            this.encodedAlgorithmIdentifier = algorithmIdentifier.getEncoded();
        } catch (IOException ex) {
            throw new XiSecurityException("could not encode AlgorithmIdentifier", ex);
        }

        ASN1ObjectIdentifier algOid = signatureAlgId.getAlgorithm();
        HashAlgoType hashAlgo;
        if (PKCSObjectIdentifiers.sha1WithRSAEncryption.equals(algOid)) {
            hashAlgo = HashAlgoType.SHA1;
        } else if (PKCSObjectIdentifiers.sha224WithRSAEncryption.equals(algOid)) {
            hashAlgo = HashAlgoType.SHA224;
        } else if (PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(algOid)) {
            hashAlgo = HashAlgoType.SHA256;
        } else if (PKCSObjectIdentifiers.sha384WithRSAEncryption.equals(algOid)) {
            hashAlgo = HashAlgoType.SHA384;
        } else if (PKCSObjectIdentifiers.sha512WithRSAEncryption.equals(algOid)) {
            hashAlgo = HashAlgoType.SHA512;
        } else if (NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224.equals(algOid)) {
            hashAlgo = HashAlgoType.SHA3_224;
        } else if (NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256.equals(algOid)) {
            hashAlgo = HashAlgoType.SHA3_256;
        } else if (NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384.equals(algOid)) {
            hashAlgo = HashAlgoType.SHA3_384;
        } else if (NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512.equals(algOid)) {
            hashAlgo = HashAlgoType.SHA3_512;
        } else {
            throw new XiSecurityException("unsupported signature algorithm " + algOid.getId());
        }

        P11SlotIdentifier slotId = identityId.slotId();
        P11Slot slot = cryptService.getSlot(slotId);
        if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_PKCS)) {
            this.mechanism = PKCS11Constants.CKM_RSA_PKCS;
        } else if (slot.supportsMechanism(PKCS11Constants.CKM_RSA_X_509)) {
            this.mechanism = PKCS11Constants.CKM_RSA_X_509;
        } else {
            switch (hashAlgo) {
            case SHA1:
                this.mechanism = PKCS11Constants.CKM_SHA1_RSA_PKCS;
                break;
            case SHA224:
                this.mechanism = PKCS11Constants.CKM_SHA224_RSA_PKCS;
                break;
            case SHA256:
                this.mechanism = PKCS11Constants.CKM_SHA256_RSA_PKCS;
                break;
            case SHA384:
                this.mechanism = PKCS11Constants.CKM_SHA384_RSA_PKCS;
                break;
            case SHA512:
                this.mechanism = PKCS11Constants.CKM_SHA512_RSA_PKCS;
                break;
            case SHA3_224:
                this.mechanism = PKCS11Constants.CKM_SHA3_224_RSA_PKCS;
                break;
            case SHA3_256:
                this.mechanism = PKCS11Constants.CKM_SHA3_256_RSA_PKCS;
                break;
            case SHA3_384:
                this.mechanism = PKCS11Constants.CKM_SHA3_384_RSA_PKCS;
                break;
            case SHA3_512:
                this.mechanism = PKCS11Constants.CKM_SHA3_512_RSA_PKCS;
                break;
            default:
                throw new RuntimeException("should not reach here, unknown HashAlgoType "
                        + hashAlgo);
            }

            if (!slot.supportsMechanism(this.mechanism)) {
                throw new XiSecurityException("unsupported signature algorithm " + algOid.getId());
            }
        }

        if (mechanism == PKCS11Constants.CKM_RSA_PKCS
                || mechanism == PKCS11Constants.CKM_RSA_X_509) {
            this.digestPkcsPrefix = SignerUtil.getDigestPkcsPrefix(hashAlgo);
            Digest digest = SignerUtil.getDigest(hashAlgo);
            this.outputStream = new DigestOutputStream(digest);
        } else {
            this.digestPkcsPrefix = null;
            this.outputStream = new ByteArrayOutputStream();
        }

        RSAPublicKey rsaPubKey = (RSAPublicKey) cryptService.getIdentity(identityId).publicKey();
        this.modulusBitLen = rsaPubKey.getModulus().bitLength();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public byte[] getEncodedAlgorithmIdentifier() {
        return Arrays.copyOf(encodedAlgorithmIdentifier, encodedAlgorithmIdentifier.length);
    }

    @Override
    public OutputStream getOutputStream() {
        if (outputStream instanceof ByteArrayOutputStream) {
            ((ByteArrayOutputStream) outputStream).reset();
        } else {
            ((DigestOutputStream) outputStream).reset();
        }
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        byte[] dataToSign;
        if (outputStream instanceof ByteArrayOutputStream) {
            dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
            ((ByteArrayOutputStream) outputStream).reset();
        } else {
            byte[] hashValue = ((DigestOutputStream) outputStream).digest();
            ((DigestOutputStream) outputStream).reset();
            dataToSign = new byte[digestPkcsPrefix.length + hashValue.length];
            System.arraycopy(digestPkcsPrefix, 0, dataToSign, 0, digestPkcsPrefix.length);
            System.arraycopy(hashValue, 0, dataToSign, digestPkcsPrefix.length, hashValue.length);
        }

        try {
            if (mechanism == PKCS11Constants.CKM_RSA_X_509) {
                dataToSign = SignerUtil.EMSA_PKCS1_v1_5_encoding(dataToSign, modulusBitLen);
            }

            return cryptService.getIdentity(identityId).sign(mechanism, null, dataToSign);
        } catch (XiSecurityException | P11TokenException ex) {
            LogUtil.error(LOG, ex, "could not sign");
            throw new RuntimeCryptoException("SignerException: " + ex.getMessage());
        }
    }

}
