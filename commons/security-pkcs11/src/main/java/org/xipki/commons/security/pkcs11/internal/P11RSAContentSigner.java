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

package org.xipki.commons.security.pkcs11.internal;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.HashAlgoType;
import org.xipki.commons.security.api.exception.SecurityException;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Slot;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.util.SignerUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
//CHECKSTYLE:SKIP
class P11RSAContentSigner implements ContentSigner {

    private static final Logger LOG = LoggerFactory.getLogger(P11RSAContentSigner.class);

    private static final Map<HashAlgoType, byte[]> digestPkcsPrefixMap = new HashMap<>();

    private final AlgorithmIdentifier algorithmIdentifier;

    private final long mechanism;

    private final OutputStream outputStream;

    private final P11CryptService cryptService;

    private final P11EntityIdentifier identityId;

    private final byte[] digestPkcsPrefix;

    private final int modulusBitLen;

    static {
        digestPkcsPrefixMap.put(HashAlgoType.SHA1,
                Hex.decode("3021300906052b0e03021a05000414"));
        digestPkcsPrefixMap.put(HashAlgoType.SHA224,
                Hex.decode("302d300d06096086480165030402040500041c"));
        digestPkcsPrefixMap.put(HashAlgoType.SHA256,
                Hex.decode("3031300d060960864801650304020105000420"));
        digestPkcsPrefixMap.put(HashAlgoType.SHA384,
                Hex.decode("3041300d060960864801650304020205000430"));
        digestPkcsPrefixMap.put(HashAlgoType.SHA512,
                Hex.decode("3051300d060960864801650304020305000440"));
    }

    P11RSAContentSigner(
            final P11CryptService cryptService,
            final P11EntityIdentifier identityId,
            final AlgorithmIdentifier signatureAlgId)
    throws SecurityException, P11TokenException {
        this.cryptService = ParamUtil.requireNonNull("cryptService", cryptService);
        this.identityId = ParamUtil.requireNonNull("identityId", identityId);
        this.algorithmIdentifier = ParamUtil.requireNonNull("signatureAlgId", signatureAlgId);

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
        } else {
            throw new SecurityException("unsupported signature algorithm " + algOid.getId());
        }

        P11SlotIdentifier slotId = identityId.getSlotId();
        P11Slot slot = cryptService.getSlot(slotId);
        if (slot.supportsMechanism(P11Constants.CKM_RSA_PKCS)) {
            this.mechanism = P11Constants.CKM_RSA_PKCS;
        } else if (slot.supportsMechanism(P11Constants.CKM_RSA_X_509)) {
            this.mechanism = P11Constants.CKM_RSA_X_509;
        } else {
            switch (hashAlgo) {
            case SHA1:
                this.mechanism = P11Constants.CKM_SHA1_RSA_PKCS;
                break;
            case SHA224:
                this.mechanism = P11Constants.CKM_SHA224_RSA_PKCS;
                break;
            case SHA256:
                this.mechanism = P11Constants.CKM_SHA256_RSA_PKCS;
                break;
            case SHA384:
                this.mechanism = P11Constants.CKM_SHA384_RSA_PKCS;
                break;
            case SHA512:
                this.mechanism = P11Constants.CKM_SHA512_RSA_PKCS;
                break;
            default:
                throw new RuntimeException("should not reach here, unknown HashAlgoType "
                        + hashAlgo);
            }

            if (!slot.supportsMechanism(this.mechanism)) {
                throw new SecurityException("unsupported signature algorithm " + algOid.getId());
            }
        }

        if (mechanism == P11Constants.CKM_RSA_PKCS || mechanism == P11Constants.CKM_RSA_X_509) {
            this.digestPkcsPrefix = digestPkcsPrefixMap.get(hashAlgo);
            Digest digest = SignerUtil.getDigest(hashAlgo);
            this.outputStream = new DigestOutputStream(digest);
        } else {
            this.digestPkcsPrefix = null;
            this.outputStream = new ByteArrayOutputStream();
        }

        RSAPublicKey rsaPubKey = (RSAPublicKey) cryptService.getIdentity(identityId).getPublicKey();
        this.modulusBitLen = rsaPubKey.getModulus().bitLength();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
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
            if (mechanism == P11Constants.CKM_RSA_X_509) {
                dataToSign = SignerUtil.EMSA_PKCS1_v1_5_encoding(dataToSign, modulusBitLen);
            }

            return cryptService.getIdentity(identityId).sign(mechanism, null, dataToSign);
        } catch (SecurityException | P11TokenException ex) {
            final String message = "could not sign";
            LOG.error(LogUtil.getErrorLog(message), ex.getClass().getName(), ex.getMessage());
            LOG.debug(message, ex);
            throw new RuntimeCryptoException("SignerException: " + ex.getMessage());
        }
    }

}
