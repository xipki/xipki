/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.security.pkcs11;

import org.eclipse.jdt.annotation.NonNull;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11EntityIdentifier implements Comparable<P11EntityIdentifier> {

    private final P11SlotIdentifier slotId;

    private final P11ObjectIdentifier objectId;

    public P11EntityIdentifier(@NonNull final P11SlotIdentifier slotId,
            @NonNull final P11ObjectIdentifier objectId) {
        this.slotId = ParamUtil.requireNonNull("slotId", slotId);
        this.objectId = ParamUtil.requireNonNull("objectId", objectId);
    }

    public P11SlotIdentifier slotId() {
        return slotId;
    }

    public P11ObjectIdentifier objectId() {
        return objectId;
    }

    @Override
    public int compareTo(final P11EntityIdentifier obj) {
        int ct = slotId.compareTo(obj.slotId);
        if (ct != 0) {
            return ct;
        }
        return objectId.compareTo(obj.objectId);
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof P11EntityIdentifier)) {
            return false;
        }

        P11EntityIdentifier ei = (P11EntityIdentifier) obj;
        return this.slotId.equals(ei.slotId) && this.objectId.equals(ei.objectId);
    }

    public boolean match(final P11SlotIdentifier slotId, final String objectLabel) {
        ParamUtil.requireNonNull("objectLabel", objectLabel);
        return this.slotId.equals(slotId)
                && objectLabel.equals(this.objectId.label());
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("slot ").append(slotId);
        sb.append(", object ").append(objectId);
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int hashCode = slotId.hashCode();
        return hashCode + 31 * objectId.hashCode();
    }

}
