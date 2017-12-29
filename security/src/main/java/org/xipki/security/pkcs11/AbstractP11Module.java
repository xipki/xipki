/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.P11UnknownEntityException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class AbstractP11Module implements P11Module {

    protected final P11ModuleConf conf;

    private final Map<P11SlotIdentifier, P11Slot> slots = new HashMap<>();

    private final List<P11SlotIdentifier> slotIds = new ArrayList<>();

    public AbstractP11Module(P11ModuleConf conf) {
        this.conf = ParamUtil.requireNonNull("conf", conf);
    }

    @Override
    public String getName() {
        return conf.name();
    }

    @Override
    public boolean isReadOnly() {
        return conf.isReadOnly();
    }

    @Override
    public P11ModuleConf getConf() {
        return conf;
    }

    protected void setSlots(Set<P11Slot> slots) {
        this.slots.clear();
        this.slotIds.clear();
        for (P11Slot slot : slots) {
            this.slots.put(slot.slotId(), slot);
            this.slotIds.add(slot.slotId());
        }

        Collections.sort(this.slotIds);
    }

    public P11Slot getSlot(P11SlotIdentifier slotId) throws P11TokenException {
        ParamUtil.requireNonNull("slotId", slotId);
        P11Slot slot = slots.get(slotId);
        if (slot == null) {
            throw new P11UnknownEntityException(slotId);
        }
        return slot;
    } // method gestSlot

    void destroySlot(long slotId) {
        P11SlotIdentifier p11SlotId = null;
        for (P11SlotIdentifier si : slots.keySet()) {
            if (CompareUtil.equalsObject(si.id(), slotId)) {
                p11SlotId = si;
                break;
            }
        }
        if (p11SlotId != null) {
            slots.remove(p11SlotId);
        }
    }

    @Override
    public List<P11SlotIdentifier> slotIdentifiers() {
        return slotIds;
    }

    @Override
    public P11SlotIdentifier getSlotIdForIndex(int index) throws P11UnknownEntityException {
        for (P11SlotIdentifier id : slotIds) {
            if (id.index() == index) {
                return id;
            }
        }
        throw new P11UnknownEntityException("could not find slot with index " + index);
    }

    @Override
    public P11SlotIdentifier getSlotIdForId(long id) throws P11UnknownEntityException {
        for (P11SlotIdentifier slotId : slotIds) {
            if (slotId.id() == id) {
                return slotId;
            }
        }
        throw new P11UnknownEntityException("could not find slot with id " + id);
    }

}
