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

package org.xipki.commons.security.api.p11;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.exception.P11TokenException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11CryptService {

    private static final Logger LOG = LoggerFactory.getLogger(P11CryptService.class);

    private P11Module module;

    public P11CryptService(
            final P11Module module)
    throws P11TokenException {
        this.module = ParamUtil.requireNonNull("module", module);
    }

    public synchronized void refresh()
    throws P11TokenException {
        LOG.info("refreshing PKCS#11 module {}", module.getName());

        List<P11SlotIdentifier> slotIds = module.getSlotIdentifiers();
        for (P11SlotIdentifier slotId : slotIds) {
            P11Slot slot;
            try {
                slot = module.getSlot(slotId);
            } catch (P11TokenException ex) {
                LogUtil.warn(LOG, ex, "P11TokenException while initializing slot " + slotId);
                continue;
            } catch (Throwable th) {
                LogUtil.warn(LOG, th, "unexpected error while initializing slot " + slotId);
                continue;
            }

            slot.refresh();
        }

        LOG.info("refreshed PKCS#11 module {}", module.getName());
    } // method refresh

    public P11Module getModule()
    throws P11TokenException {
        return module;
    }

    public P11Slot getSlot(
            final P11SlotIdentifier slotId)
    throws P11TokenException {
        return module.getSlot(slotId);
    }

    public P11Identity getIdentity(
            final P11EntityIdentifier identityId)
    throws P11TokenException {
        ParamUtil.requireNonNull("identityId", identityId);
        return module.getSlot(identityId.getSlotId()).getIdentity(identityId.getObjectId());
    }

    @Override
    public String toString() {
        return module.toString();
    }

}
