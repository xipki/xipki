/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
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

import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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

abstract class AbstractP11DSAContentSigner implements ContentSigner
{
    private static final Logger LOG = LoggerFactory.getLogger(AbstractP11DSAContentSigner.class);

    private final AlgorithmIdentifier algorithmIdentifier;
    private final DigestOutputStream outputStream;

    protected final P11CryptService cryptService;
    protected final P11SlotIdentifier slot;
    protected final P11KeyIdentifier keyId;

    protected abstract byte[] CKM_SIGN(byte[] hashValue)
    throws SignerException;

    protected AbstractP11DSAContentSigner(
            P11CryptService cryptService,
            P11SlotIdentifier slot,
            P11KeyIdentifier keyId,
            AlgorithmIdentifier signatureAlgId)
    throws NoSuchAlgorithmException, OperatorCreationException
    {
        ParamChecker.assertNotNull("slot", slot);
        ParamChecker.assertNotNull("cryptService", cryptService);
        ParamChecker.assertNotNull("keyId", keyId);
        ParamChecker.assertNotNull("signatureAlgId", signatureAlgId);

        this.slot = slot;
        this.algorithmIdentifier = signatureAlgId;
        this.keyId = keyId;
        this.cryptService = cryptService;

        AlgorithmIdentifier digAlgId = SignerUtil.extractDigesetAlgorithmIdentifier(signatureAlgId);

        Digest digest = BcDefaultDigestProvider.INSTANCE.get(digAlgId);

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
        try
        {
            return CKM_SIGN(hashValue);
        } catch (SignerException e)
        {
            LOG.warn("SignerException: {}", e.getMessage());
            LOG.debug("SignerException", e);
            throw new RuntimeCryptoException("SignerException: " + e.getMessage());
        } catch (Throwable t)
        {
            final String message = "Throwable";
            if(LOG.isWarnEnabled())
            {
                LOG.warn(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
            }
            LOG.debug(message, t);
            throw new RuntimeCryptoException(t.getClass().getName() + ": " + t.getMessage());
        }
    }
}
