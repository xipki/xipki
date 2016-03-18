/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

import java.math.BigInteger;

import javax.annotation.Nonnull;

import org.bouncycastle.util.encoders.Hex;
import org.xipki.commons.common.util.CompareUtil;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class P11KeyIdentifier implements Comparable<P11KeyIdentifier> {

    private final byte[] keyId;

    private final String keyIdHex;

    private final String keyLabel;

    public P11KeyIdentifier(
            @Nonnull final byte[] keyId,
            @Nonnull final String keyLabel) {
        this.keyId = ParamUtil.requireNonNull("keyId", keyId);
        this.keyLabel = ParamUtil.requireNonBlank("keyLabel", keyLabel);
        this.keyIdHex = Hex.toHexString(keyId).toUpperCase();
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public String getKeyIdHex() {
        return keyIdHex;
    }

    public String getKeyLabel() {
        return keyLabel;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (keyIdHex != null) {
            sb.append("key-id: ").append(keyIdHex);
            if (keyLabel != null) {
                sb.append(", ");
            }
        }
        if (keyLabel != null) {
            sb.append("key-label: ").append(keyLabel);
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int hashCode = 0;
        if (keyId != null) {
            hashCode = new BigInteger(1, keyId).hashCode();
        }

        if (keyLabel != null) {
            hashCode += 31 * keyLabel.hashCode();
        }

        return hashCode;
    }

    @Override
    public boolean equals(
            final Object obj) {
        if (this == obj) {
            return true;
        }

        if (!(obj instanceof P11KeyIdentifier)) {
            return false;
        }

        P11KeyIdentifier another = (P11KeyIdentifier) obj;
        if (!CompareUtil.equalsObject(this.keyId, another.keyId)) {
            return false;
        }

        return this.keyLabel.equals(another.keyLabel);
    }

    @Override
    public int compareTo(
            final P11KeyIdentifier obj) {
        ParamUtil.requireNonNull("obj", obj);
        if (this == obj) {
            return 0;
        }

        if (keyLabel == null) {
            return (obj.keyLabel == null)
                    ? 0
                    : 1;
        } else {
            return (obj.keyLabel == null)
                    ? -1
                    : keyLabel.compareTo(obj.keyLabel);
        }
    }

}
