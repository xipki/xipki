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

package org.xipki.commons.security.impl.p11.proxy;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.pkcs11proxy.common.ASN1SlotIdentifier;
import org.xipki.commons.pkcs11proxy.common.P11ProxyConstants;
import org.xipki.commons.security.api.p11.AbstractP11Module;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11Slot;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class RemoteP11Module extends AbstractP11Module {

    private static final Logger LOG = LoggerFactory.getLogger(RemoteP11Module.class);

    private final P11Communicator communicator;

    RemoteP11Module(
            final P11ModuleConf moduleConf,
            final P11Communicator communicator)
    throws P11TokenException {
        super(moduleConf);
        this.communicator = ParamUtil.requireNonNull("communicator", communicator);
        ASN1Encodable resp = communicator.send(P11ProxyConstants.ACTION_getSlotIds, null);
        if (!(resp instanceof ASN1Sequence)) {
            throw new P11TokenException("response is not ASN1Sequence, but "
                    + resp.getClass().getName());
        }

        ASN1Sequence seq = (ASN1Sequence) resp;
        final int n = seq.size();

        Set<P11Slot> slots = new HashSet<>();
        for (int i = 0; i < n; i++) {
            ASN1SlotIdentifier asn1SlotId;
            try {
                ASN1Encodable obj = seq.getObjectAt(i);
                asn1SlotId = ASN1SlotIdentifier.getInstance(obj);
            } catch (Exception ex) {
                throw new P11TokenException(ex.getMessage(), ex);
            }

            P11SlotIdentifier slotId = asn1SlotId.getSlotId();
            if (!moduleConf.isSlotIncluded(slotId)) {
                continue;
            }

            P11Slot slot = new RemoteP11Slot(getName(), slotId, moduleConf.getP11MechanismFilter(),
                    communicator);
            if (moduleConf.isSlotIncluded(slotId)) {
                slots.add(slot);
            }
        }
        setSlots(slots);
    }

    void close() {
        for (P11SlotIdentifier slotId : getSlotIdentifiers()) {
            try {
                getSlot(slotId).close();
            } catch (Throwable th) {
                LOG.error("could not close PKCS#11 slot {}: {}", slotId, th.getMessage());
                LOG.debug("could not close PKCS#11 slot " + slotId, th);
            }
        }
    }

    P11Communicator getCommunicator() {
        return communicator;
    }

}
