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

package org.xipki.commons.security.impl.p11;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.operator.ContentSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.HashAlgoType;
import org.xipki.commons.security.api.SecurityException;
import org.xipki.commons.security.api.p11.P11Constants;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Slot;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.parameters.P11RSAPkcsPssParams;
import org.xipki.commons.security.api.util.SignerUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
class P11RSAPSSContentSigner implements ContentSigner {
    // CHECKSTYLE:SKIP
    private static class PSSSignerOutputStream extends OutputStream {

        private PSSSigner pssSigner;

        PSSSignerOutputStream(PSSSigner pssSigner) {
            this.pssSigner = pssSigner;
        }

        @Override
        public void write(
                final int oneByte)
        throws IOException {
            pssSigner.update((byte) oneByte);
        }

        @Override
        public void write(
                final byte[] bytes)
        throws IOException {
            pssSigner.update(bytes, 0, bytes.length);
        }

        @Override
        public void write(
                final byte[] bytes,
                final int off,
                final int len)
        throws IOException {
            pssSigner.update(bytes, off, len);
        }

        public void reset() {
            pssSigner.reset();
        }

        @Override
        public void flush()
        throws IOException {
        }

        @Override
        public void close()
        throws IOException {
        }

        byte[] generateSignature()
        throws DataLengthException, CryptoException {
            byte[] signature = pssSigner.generateSignature();
            pssSigner.reset();
            return signature;
        }

    } // class PSSSignerOutputStream

    private static final Logger LOG = LoggerFactory.getLogger(P11RSAPSSContentSigner.class);

    private final AlgorithmIdentifier algorithmIdentifier;

    private final P11CryptService cryptService;

    private final P11EntityIdentifier identityId;

    private final long mechanism;

    private final P11RSAPkcsPssParams parameters;

    private final OutputStream outputStream;

    P11RSAPSSContentSigner(
            final P11CryptService cryptService,
            final P11EntityIdentifier identityId,
            final AlgorithmIdentifier signatureAlgId,
            final SecureRandom random)
    throws SecurityException, P11TokenException {
        this.cryptService = ParamUtil.requireNonNull("cryptService", cryptService);
        this.identityId = ParamUtil.requireNonNull("identityId", identityId);
        this.algorithmIdentifier = ParamUtil.requireNonNull("signatureAlgId", signatureAlgId);
        ParamUtil.requireNonNull("random", random);

        if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(signatureAlgId.getAlgorithm())) {
            throw new SecurityException("unsupported signature algorithm "
                    + signatureAlgId.getAlgorithm());
        }

        RSASSAPSSparams asn1Params = RSASSAPSSparams.getInstance(signatureAlgId.getParameters());
        ASN1ObjectIdentifier digestAlgOid = asn1Params.getHashAlgorithm().getAlgorithm();
        HashAlgoType hashAlgo = HashAlgoType.getHashAlgoType(digestAlgOid);
        if (hashAlgo == null) {
            throw new SecurityException("unsupported hash algorithm " + digestAlgOid.getId());
        }

        P11SlotIdentifier slotId = identityId.getSlotId();
        P11Slot slot = cryptService.getSlot(slotId);
        if (slot.supportsMechanism(P11Constants.CKM_RSA_PKCS_PSS)) {
            this.mechanism = P11Constants.CKM_RSA_PKCS_PSS;
            this.parameters = new P11RSAPkcsPssParams(asn1Params);
            AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier(hashAlgo.getOid()), DERNull.INSTANCE);
            Digest digest = SignerUtil.getDigest(digAlgId);
            this.outputStream = new DigestOutputStream(digest);
        } else if (slot.supportsMechanism(P11Constants.CKM_RSA_X_509)) {
            this.mechanism = P11Constants.CKM_RSA_X_509;
            this.parameters = null;
            AsymmetricBlockCipher cipher = new P11PlainRSASigner();
            P11RSAKeyParameter keyParam;
            try {
                keyParam = P11RSAKeyParameter.getInstance(cryptService, identityId);
            } catch (InvalidKeyException ex) {
                throw new SecurityException(ex.getMessage(), ex);
            }
            PSSSigner pssSigner = SignerUtil.createPSSRSASigner(signatureAlgId, cipher);
            pssSigner.init(true, new ParametersWithRandom(keyParam, random));
            this.outputStream = new PSSSignerOutputStream(pssSigner);
        } else {
            switch (hashAlgo) {
            case SHA1:
                this.mechanism = P11Constants.CKM_SHA1_RSA_PKCS_PSS;
                break;
            case SHA224:
                this.mechanism = P11Constants.CKM_SHA224_RSA_PKCS_PSS;
                break;
            case SHA256:
                this.mechanism = P11Constants.CKM_SHA256_RSA_PKCS_PSS;
                break;
            case SHA384:
                this.mechanism = P11Constants.CKM_SHA384_RSA_PKCS_PSS;
                break;
            case SHA512:
                this.mechanism = P11Constants.CKM_SHA512_RSA_PKCS_PSS;
                break;
            default:
                throw new RuntimeException("should not reach here, unknown HashAlgoType "
                        + hashAlgo);
            }

            if (!slot.supportsMechanism(this.mechanism)) {
                throw new SecurityException("unsupported signature algorithm "
                        + PKCSObjectIdentifiers.id_RSASSA_PSS.getId() + " with " + hashAlgo);
            }

            this.parameters = new P11RSAPkcsPssParams(asn1Params);
            this.outputStream = new ByteArrayOutputStream();
        }
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        if (outputStream instanceof ByteArrayOutputStream) {
            ((ByteArrayOutputStream) outputStream).reset();
        } else if (outputStream instanceof DigestOutputStream) {
            ((DigestOutputStream) outputStream).reset();
        } else {
            ((PSSSignerOutputStream) outputStream).reset();
        }

        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        if (outputStream instanceof PSSSignerOutputStream) {
            try {
                return ((PSSSignerOutputStream) outputStream).generateSignature();
            } catch (CryptoException ex) {
                LOG.warn("CryptoException: {}", ex.getMessage());
                LOG.debug("CryptoException", ex);
                throw new RuntimeCryptoException("CryptoException: " + ex.getMessage());
            }
        }

        byte[] dataToSign;
        if (outputStream instanceof ByteArrayOutputStream) {
            dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
        } else {
            dataToSign = ((DigestOutputStream) outputStream).digest();
        }

        try {
            return cryptService.getIdentity(identityId).sign(mechanism, parameters, dataToSign);
        } catch (SecurityException | P11TokenException ex) {
            LOG.warn("could not sign: {}", ex.getMessage());
            LOG.debug("could not sign", ex);
            throw new RuntimeCryptoException("SignerException: " + ex.getMessage());
        }

    }

}
