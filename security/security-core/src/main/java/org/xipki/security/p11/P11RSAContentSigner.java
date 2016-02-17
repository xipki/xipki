/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
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

package org.xipki.security.p11;

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
import org.xipki.security.SignerUtil;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.common.LogUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class P11RSAContentSigner implements ContentSigner
{
    private static final Logger LOG = LoggerFactory.getLogger(P11RSAContentSigner.class);
    private final AlgorithmIdentifier algorithmIdentifier;
    private final DigestOutputStream outputStream;

    private final P11CryptService cryptService;
    private final P11SlotIdentifier slot;
    private final P11KeyIdentifier keyId;

    private final AlgorithmIdentifier digAlgId;

    public P11RSAContentSigner(
            P11CryptService cryptService,
            P11SlotIdentifier slot,
            P11KeyIdentifier keyId,
            AlgorithmIdentifier signatureAlgId)
    throws NoSuchAlgorithmException, NoSuchPaddingException, OperatorCreationException
    {
        ParamChecker.assertNotNull("slot", slot);
        ParamChecker.assertNotNull("cryptService", cryptService);
        ParamChecker.assertNotNull("keyId", keyId);
        ParamChecker.assertNotNull("signatureAlgId", signatureAlgId);

        if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(signatureAlgId.getAlgorithm()))
        {
            throw new IllegalArgumentException("Unsupported signature algorithm " + signatureAlgId.getAlgorithm());
        }

        this.slot = slot;
        this.algorithmIdentifier = signatureAlgId;
        this.keyId = keyId;

        this.digAlgId = SignerUtil.extractDigesetAlgorithmIdentifier(signatureAlgId);
        Digest digest = BcDefaultDigestProvider.INSTANCE.get(digAlgId);

        this.cryptService = cryptService;
        this.outputStream = new DigestOutputStream(digest);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream()
    {
        outputStream.reset();
        return outputStream;
    }

    @Override
    public byte[] getSignature()
    {
        byte[] hashValue = outputStream.digest();
        DigestInfo digestInfo = new DigestInfo(digAlgId, hashValue);
        byte[] encodedDigestInfo;

        try
        {
            encodedDigestInfo = digestInfo.getEncoded();
        } catch (IOException e)
        {
            LOG.warn("IOException: {}", e.getMessage());
            LOG.debug("IOException", e);
            throw new RuntimeCryptoException("IOException: " + e.getMessage());
        }

        try
        {
            return cryptService.CKM_RSA_PKCS(encodedDigestInfo, slot, keyId);
        } catch (SignerException e)
        {
            final String message = "SignerException";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            throw new RuntimeCryptoException("SignerException: " + e.getMessage());
        }
    }

}
