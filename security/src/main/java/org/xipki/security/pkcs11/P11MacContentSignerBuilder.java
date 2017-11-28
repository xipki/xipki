/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs11;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.DefaultConcurrentContentSigner;
import org.xipki.security.bc.XiContentSigner;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.XiSecurityException;

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

        List<XiContentSigner> signers = new ArrayList<>(parallelism);
        for (int i = 0; i < parallelism; i++) {
            XiContentSigner signer = new P11MacContentSigner(
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
