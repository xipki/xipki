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

package org.xipki.commons.security.impl.p11;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11RSAContentSigner implements ContentSigner {

    private static final Logger LOG = LoggerFactory.getLogger(P11RSAContentSigner.class);

    private final AlgorithmIdentifier algorithmIdentifier;

    private final DigestOutputStream outputStream;

    private final P11CryptService cryptService;

    private final P11SlotIdentifier slot;

    private final P11KeyIdentifier keyId;

    private final AlgorithmIdentifier digAlgId;

    public P11RSAContentSigner(
            final P11CryptService cryptService,
            final P11SlotIdentifier slot,
            final P11KeyIdentifier keyId,
            final AlgorithmIdentifier signatureAlgId)
    throws NoSuchAlgorithmException, NoSuchPaddingException, OperatorCreationException {
        this.slot = ParamUtil.requireNonNull("slot", slot);
        this.cryptService = ParamUtil.requireNonNull("cryptService", cryptService);
        this.keyId = ParamUtil.requireNonNull("keyId", keyId);
        this.algorithmIdentifier = ParamUtil.requireNonNull("signatureAlgId", signatureAlgId);

        if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(signatureAlgId.getAlgorithm())) {
            throw new IllegalArgumentException("unsupported signature algorithm "
                    + signatureAlgId.getAlgorithm());
        }

        this.digAlgId = AlgorithmUtil.extractDigesetAlgorithmIdentifier(signatureAlgId);
        Digest digest = BcDefaultDigestProvider.INSTANCE.get(digAlgId);
        this.outputStream = new DigestOutputStream(digest);
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
        byte[] hashValue = outputStream.digest();
        DigestInfo digestInfo = new DigestInfo(digAlgId, hashValue);
        byte[] encodedDigestInfo;

        try {
            encodedDigestInfo = digestInfo.getEncoded();
        } catch (IOException ex) {
            LOG.warn("IOException: {}", ex.getMessage());
            LOG.debug("IOException", ex);
            throw new RuntimeCryptoException("IOException: " + ex.getMessage());
        }

        try {
            return cryptService.CKM_RSA_PKCS(encodedDigestInfo, slot, keyId);
        } catch (SignerException ex) {
            final String message = "SignerException";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
            throw new RuntimeCryptoException("SignerException: " + ex.getMessage());
        }
    }

}
