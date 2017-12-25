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

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11SlotIdentifier implements Comparable<P11SlotIdentifier> {

    private final int index;

    private final long id;

    public P11SlotIdentifier(final int index, final long id) {
        this.index = ParamUtil.requireMin("index", index, 0);
        this.id = ParamUtil.requireMin("id", id, 0);
    }

    public int index() {
        return index;
    }

    public long id() {
        return id;
    }

    @Override
    public boolean equals(final Object obj) {
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
        sb.append("(index = ").append(index).append(", id = ").append(id).append(")");
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int hashCode = Long.hashCode(id);
        hashCode += 31 * index;
        return hashCode;
    }

    @Override
    public int compareTo(final P11SlotIdentifier obj) {
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
