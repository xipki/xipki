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

package org.xipki.commons.security.speed.p11;

import java.security.cert.X509Certificate;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.LoadExecutor;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.NoIdleSignerException;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11WritableSlot;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11SignLoadTest extends LoadExecutor {

    class Testor implements Runnable {

        @Override
        public void run() {
            ContentSigner singleSigner;
            try {
                singleSigner = signer.borrowContentSigner();
            } catch (NoIdleSignerException e) {
                account(1, 1);
                return;
            }

            while (!stop() && getErrorAccout() < 1) {
                try {
                    singleSigner.getOutputStream().write(new byte[]{1, 2, 3, 4});
                    singleSigner.getSignature();
                    account(1, 0);
                } catch (Exception e) {
                    account(1, 1);
                }
            }

            signer.returnContentSigner(singleSigner);
            close();
        }

    } // class Testor

    private static final Logger LOG = LoggerFactory.getLogger(P11SignLoadTest.class);

    private final P11WritableSlot slot;

    private final ConcurrentContentSigner signer;

    private final P11KeyIdentifier keyId;

    public P11SignLoadTest(
            final SecurityFactory securityFactory,
            final P11WritableSlot slot,
            final String signatureAlgorithm,
            final P11KeyIdentifier keyId,
            final String description)
    throws SignerException {
        super(description + "\nsignature algorithm: " + signatureAlgorithm);

        ParamUtil.assertNotNull("securityFactory", securityFactory);
        ParamUtil.assertNotNull("slot", slot);
        ParamUtil.assertNotBlank("signatureAlgorithm", signatureAlgorithm);
        ParamUtil.assertNotNull("keyId", keyId);

        this.slot = slot;
        this.keyId = keyId;

        String signerConf = getPkcs11SignerConf(
                slot.getModuleName(), slot.getSlotIdentifier(), keyId, signatureAlgorithm, 20);
        this.signer = securityFactory.createSigner("PKCS11", signerConf, (X509Certificate) null);

    }

    private void close() {
        try {
            slot.removeKeyAndCerts(keyId);
        } catch (Exception e) {
            LOG.error("could not delete PKCS#11 key {}", keyId);
        }
    }

    @Override
    protected Runnable getTestor()
    throws Exception {
        return new Testor();
    }

    private static String getPkcs11SignerConf(
            final String pkcs11ModuleName,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId,
            final String signatureAlgorithm,
            final int parallelism) {
        ParamUtil.assertNotNull("algo", signatureAlgorithm);
        ParamUtil.assertNotNull("keyId", keyId);

        ConfPairs conf = new ConfPairs("algo", signatureAlgorithm);
        conf.putPair("parallelism", Integer.toString(parallelism));

        if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
            conf.putPair("module", pkcs11ModuleName);
        }

        if (slotId.getSlotId() != null) {
            conf.putPair("slot-id", slotId.getSlotId().toString());
        } else {
            conf.putPair("slot", slotId.getSlotIndex().toString());
        }

        if (keyId.getKeyId() != null) {
            conf.putPair("key-id", Hex.toHexString(keyId.getKeyId()));
        }

        if (keyId.getKeyLabel() != null) {
            conf.putPair("key-label", keyId.getKeyLabel());
        }

        return conf.getEncoded();
    }

}
