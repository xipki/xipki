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

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11ObjectIdentifier implements Comparable<P11ObjectIdentifier> {

    private final byte[] id;

    private final String idHex;

    private final String label;

    /**
     * @param id
     *          Identifier. Must not be {@code null}.
     * @param label
     *          Label. Must not be {@code null}.
     */
    public P11ObjectIdentifier(final byte[] id, final String label) {
        this.id = ParamUtil.requireNonNull("id", id);
        this.label = ParamUtil.requireNonNull("label", label);
        this.idHex = Hex.toHexString(id).toUpperCase();
    }

    public byte[] id() {
        return id;
    }

    public boolean matchesId(final byte[] id) {
        return Arrays.equals(id, this.id);
    }

    public String idHex() {
        return idHex;
    }

    public String label() {
        return label;
    }

    public char[] labelChars() {
        return label.toCharArray();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(50);
        sb.append("(id = ").append(idHex).append(", label = ").append(label).append(")");
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int hashCode = new BigInteger(1, id).hashCode();
        hashCode += 31 * label.hashCode();
        return hashCode;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }

        if (!(obj instanceof P11ObjectIdentifier)) {
            return false;
        }

        P11ObjectIdentifier another = (P11ObjectIdentifier) obj;
        return Arrays.equals(id, another.id) && label.equals(another.label);
    }

    @Override
    public int compareTo(final P11ObjectIdentifier obj) {
        ParamUtil.requireNonNull("obj", obj);
        if (this == obj) {
            return 0;
        }

        return label.compareTo(obj.label);
    }

}
