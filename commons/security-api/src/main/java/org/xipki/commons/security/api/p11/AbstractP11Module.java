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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xipki.commons.common.util.CompareUtil;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class AbstractP11Module implements P11Module {

    protected final P11ModuleConf moduleConf;

    private final Map<P11SlotIdentifier, P11Slot> slots = new HashMap<>();

    private final List<P11SlotIdentifier> slotIds = new ArrayList<>();

    public AbstractP11Module(P11ModuleConf moduleConf) {
        this.moduleConf = ParamUtil.requireNonNull("moduleConf", moduleConf);
    }

    @Override
    public String getName() {
        return moduleConf.getName();
    }

    protected void setSlots(
            final Set<P11Slot> slots) {
        this.slots.clear();
        this.slotIds.clear();
        for (P11Slot slot : slots) {
            this.slots.put(slot.getSlotId(), slot);
            this.slotIds.add(slot.getSlotId());
        }

        Collections.sort(this.slotIds);
    }

    public P11Slot getSlot(
            final P11SlotIdentifier slotId)
    throws P11TokenException {
        ParamUtil.requireNonNull("slotId", slotId);
        P11Slot slot = slots.get(slotId);
        if (slot == null) {
            throw new P11UnknownEntityException(slotId);
        }
        return slot;
    } // method gestSlot

    void destroySlot(
            final long slotId) {
        P11SlotIdentifier p11SlotId = null;
        for (P11SlotIdentifier si : slots.keySet()) {
            if (CompareUtil.equalsObject(si.getId(), slotId)) {
                p11SlotId = si;
                break;
            }
        }
        if (p11SlotId != null) {
            slots.remove(p11SlotId);
        }
    }

    @Override
    public List<P11SlotIdentifier> getSlotIdentifiers() {
        return slotIds;
    }

    @Override
    public P11SlotIdentifier getSlotIdForIndex(
            final int index)
    throws P11UnknownEntityException {
        for (P11SlotIdentifier id : slotIds) {
            if (id.getIndex() == index) {
                return id;
            }
        }
        throw new P11UnknownEntityException("could not find slot with index " + index);
    }

    @Override
    public P11SlotIdentifier getSlotIdForId(
            final long id)
    throws P11UnknownEntityException {
        for (P11SlotIdentifier slotId : slotIds) {
            if (slotId.getId() == id) {
                return slotId;
            }
        }
        throw new P11UnknownEntityException("could not find slot with id " + id);
    }

}
