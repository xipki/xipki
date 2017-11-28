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

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.P11TokenException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11CryptService {

    private static final Logger LOG = LoggerFactory.getLogger(P11CryptService.class);

    private P11Module module;

    public P11CryptService(final P11Module module) throws P11TokenException {
        this.module = ParamUtil.requireNonNull("module", module);
    }

    public synchronized void refresh() throws P11TokenException {
        LOG.info("refreshing PKCS#11 module {}", module.getName());

        List<P11SlotIdentifier> slotIds = module.slotIdentifiers();
        for (P11SlotIdentifier slotId : slotIds) {
            P11Slot slot;
            try {
                slot = module.getSlot(slotId);
            } catch (P11TokenException ex) {
                LogUtil.warn(LOG, ex, "P11TokenException while initializing slot " + slotId);
                continue;
            } catch (Throwable th) {
                LOG.error("unexpected error while initializing slot " + slotId, th);
                continue;
            }

            slot.refresh();
        }

        LOG.info("refreshed PKCS#11 module {}", module.getName());
    } // method refresh

    public P11Module module() throws P11TokenException {
        return module;
    }

    public P11Slot getSlot(final P11SlotIdentifier slotId) throws P11TokenException {
        return module.getSlot(slotId);
    }

    public P11Identity getIdentity(final P11EntityIdentifier identityId) throws P11TokenException {
        ParamUtil.requireNonNull("identityId", identityId);
        return module.getSlot(identityId.slotId()).getIdentity(identityId.objectId());
    }

    @Override
    public String toString() {
        return module.toString();
    }

}
