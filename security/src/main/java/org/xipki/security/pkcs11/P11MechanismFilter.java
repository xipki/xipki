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

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11MechanismFilter {

    private static final class SingleFilter {

        private final Set<P11SlotIdFilter> slots;

        private final Collection<Long> mechanisms;

        private SingleFilter(Set<P11SlotIdFilter> slots, Collection<Long> mechanisms) {
            this.slots = slots;
            this.mechanisms = CollectionUtil.isEmpty(mechanisms) ? null : mechanisms;
        }

        public boolean match(P11SlotIdentifier slot) {
            if (slots == null) {
                return true;
            }
            for (P11SlotIdFilter m : slots) {
                if (m.match(slot)) {
                    return true;
                }
            }

            return false;
        }

        public boolean isMechanismSupported(long mechanism) {
            if (mechanisms == null) {
                return true;
            }

            return mechanisms.contains(mechanism);
        }

    } // class SingleFilter

    private final List<SingleFilter> singleFilters;

    P11MechanismFilter() {
        singleFilters = new LinkedList<>();
    }

    void addEntry(Set<P11SlotIdFilter> slots, Collection<Long> mechanisms) {
        singleFilters.add(new SingleFilter(slots, mechanisms));
    }

    public boolean isMechanismPermitted(P11SlotIdentifier slotId, long mechanism) {
        ParamUtil.requireNonNull("slotId", slotId);
        if (CollectionUtil.isEmpty(singleFilters)) {
            return true;
        }

        for (SingleFilter sr : singleFilters) {
            if (sr.match(slotId)) {
                return sr.isMechanismSupported(mechanism);
            }
        }

        return true;
    }

}
