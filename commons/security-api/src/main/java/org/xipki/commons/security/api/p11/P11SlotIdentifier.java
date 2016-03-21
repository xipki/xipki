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

import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11SlotIdentifier implements Comparable<P11SlotIdentifier> {

    private final int index;

    private final long id;

    public P11SlotIdentifier(
            final int index,
            final long id) {
        this.index = ParamUtil.requireMin("index", index, 0);
        this.id = ParamUtil.requireMin("id", id, 0);
    }

    public int getIndex() {
        return index;
    }

    public long getId() {
        return id;
    }

    @Override
    public boolean equals(
            final Object obj) {
        if (this == obj) {
            return true;
        }

        if (!(obj instanceof P11SlotIdentifier)) {
            return false;
        }

        P11SlotIdentifier another = (P11SlotIdentifier) obj;
        return this.id == another.id && this.index == another.index;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(30);
        sb.append("slot (index = ").append(index).append(", id = ").append(id).append(")");
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int hashCode = Long.hashCode(id);
        hashCode += 31 * index;
        return hashCode;
    }

    @Override
    public int compareTo(
            final P11SlotIdentifier obj) {
        ParamUtil.requireNonNull("obj", obj);
        if (this == obj) {
            return 0;
        }

        int sign = index - obj.index;
        if (sign > 0) {
            return 1;
        } else if (sign < 0) {
            return -1;
        } else {
            return 0;
        }
    }

}
