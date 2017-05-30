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

package org.xipki.commons.security.pkcs11;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.ConcurrentContentSigner;
import org.xipki.commons.security.DefaultConcurrentContentSigner;
import org.xipki.commons.security.exception.P11TokenException;
import org.xipki.commons.security.exception.XiSecurityException;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class P11MacContentSignerBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(P11MacContentSignerBuilder.class);

    private final P11CryptService cryptService;

    private final P11EntityIdentifier identityId;

    public P11MacContentSignerBuilder(final P11CryptService cryptService,
            final P11EntityIdentifier identityId)
            throws XiSecurityException, P11TokenException {
        this.cryptService = ParamUtil.requireNonNull("cryptService", cryptService);
        this.identityId = ParamUtil.requireNonNull("identityId", identityId);
    } // constructor

    public ConcurrentContentSigner createSigner(final AlgorithmIdentifier signatureAlgId,
            final int parallelism) throws XiSecurityException, P11TokenException {
        ParamUtil.requireMin("parallelism", parallelism, 1);

        List<ContentSigner> signers = new ArrayList<>(parallelism);
        for (int i = 0; i < parallelism; i++) {
            ContentSigner signer = new P11MacContentSigner(
                    cryptService, identityId, signatureAlgId);
            signers.add(signer);
        } // end for

        final boolean mac = true;
        DefaultConcurrentContentSigner concurrentSigner;
        try {
            concurrentSigner = new DefaultConcurrentContentSigner(mac, signers, null);
        } catch (NoSuchAlgorithmException ex) {
            throw new XiSecurityException(ex.getMessage(), ex);
        }

        try {
            byte[] sha1HashOfKey = cryptService.getIdentity(identityId).digestSecretKey(
                    PKCS11Constants.CKM_SHA_1);
            concurrentSigner.setSha1DigestOfMacKey(sha1HashOfKey);
        } catch (P11TokenException | XiSecurityException ex) {
            LogUtil.warn(LOG, ex, "could not compute the digest of secret key " + identityId);
        }

        return concurrentSigner;
    } // method createSigner

}
