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

import javax.annotation.Nonnull;

import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11EntityIdentifier implements Comparable<P11EntityIdentifier> {

    private final P11SlotIdentifier slotId;

    private final P11KeyIdentifier keyId;

    public P11EntityIdentifier(
            @Nonnull final P11SlotIdentifier slotId,
            @Nonnull final P11KeyIdentifier keyId) {
        this.slotId = ParamUtil.requireNonNull("slotId", slotId);
        this.keyId = ParamUtil.requireNonNull("keyId", keyId);
    }

    public P11SlotIdentifier getSlotId() {
        return slotId;
    }

    public P11KeyIdentifier getKeyId() {
        return keyId;
    }

    @Override
    public int compareTo(
            final P11EntityIdentifier obj) {
        int ct = slotId.compareTo(obj.slotId);
        if (ct != 0) {
            return ct;
        }
        return keyId.compareTo(obj.keyId);
    }

    @Override
    public boolean equals(
            final Object obj) {
        if (!(obj instanceof P11EntityIdentifier)) {
            return false;
        }

        P11EntityIdentifier ei = (P11EntityIdentifier) obj;
        return this.slotId.equals(ei.slotId) && this.keyId.equals(ei.getKeyId());
    }

    public boolean match(
            final P11SlotIdentifier slotId,
            final String keyLabel) {
        ParamUtil.requireNonNull("keyLabel", keyLabel);
        return this.slotId.equals(slotId)
                && keyLabel.equals(this.keyId.getLabel());
    }

    @Override
    public String toString() {
        // FIMXE: implement me
        return super.toString();
    }

    @Override
    public int hashCode() {
        // FIXME: implement me
        return 0;
    }

}
