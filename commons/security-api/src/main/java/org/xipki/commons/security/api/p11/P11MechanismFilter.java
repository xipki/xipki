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

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11MechanismFilter {

    private static final class SingleFilter {

        private final Set<P11SlotIdFilter> slots;

        private final Collection<Long> mechanisms;

        private SingleFilter(
                final Set<P11SlotIdFilter> slots,
                final Collection<Long> mechanisms) {
            this.slots = slots;
            if (CollectionUtil.isEmpty(mechanisms)) {
                this.mechanisms = null;
            } else {
                this.mechanisms = mechanisms;
            }
        }

        public boolean match(
                final P11SlotIdentifier slot) {
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

        public boolean isMechanismSupported(
            final long mechanism) {
            if (mechanisms == null) {
                return true;
            }

            return mechanisms.contains(mechanism);
        }

    } // class SingleRetriever

    private final List<SingleFilter> singleFilters;

    P11MechanismFilter() {
        singleFilters = new LinkedList<>();
    }

    void addEntry(
            final Set<P11SlotIdFilter> slots,
            final Collection<Long> mechanisms) {
        singleFilters.add(new SingleFilter(slots, mechanisms));
    }

    public boolean isMechanismPermitted(
            final P11SlotIdentifier slotId,
            final long mechanism) {
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
