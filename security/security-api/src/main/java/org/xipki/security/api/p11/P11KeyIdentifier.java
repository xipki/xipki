/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.security.api.p11;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

/**
 * @author Lijun Liao
 */

public class P11KeyIdentifier implements Comparable<P11KeyIdentifier>
{
    private final byte[] keyId;
    private final String keyIdHex;
    private final String keyLabel;

    public P11KeyIdentifier(
            final byte[] keyId,
            final String keyLabel)
    {
        if (keyId == null && keyLabel == null)
        {
            throw new IllegalArgumentException(
                    "at least one of keyId an keyLabel must be non-null");
        }
        this.keyId = keyId;
        this.keyIdHex = (keyId == null)
                ? null
                : new String(Hex.encode(keyId)).toUpperCase();
        this.keyLabel = keyLabel;
    }

    public P11KeyIdentifier(
            final byte[] keyId)
    {
        if (keyId == null)
        {
            throw new IllegalArgumentException("keyId could not be null");
        }
        this.keyId = keyId;
        this.keyIdHex = new String(Hex.encode(keyId)).toUpperCase();
        this.keyLabel = null;
    }

    public P11KeyIdentifier(
            final String keyLabel)
    {
        if (keyLabel == null)
        {
            throw new IllegalArgumentException("keyLabel could not be null");
        }
        this.keyId = null;
        this.keyIdHex = null;
        this.keyLabel = keyLabel;
    }

    public byte[] getKeyId()
    {
        return keyId;
    }

    public String getKeyIdHex()
    {
        return keyIdHex;
    }

    public String getKeyLabel()
    {
        return keyLabel;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        if (keyIdHex != null)
        {
            sb.append("key-id: ").append(keyIdHex);
            if (keyLabel != null)
            {
                sb.append(", ");
            }
        }
        if (keyLabel != null)
        {
            sb.append("key-label: ").append(keyLabel);
        }
        return sb.toString();
    }

    @Override
    public boolean equals(
            final Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (o instanceof P11KeyIdentifier == false)
        {
            return false;
        }

        P11KeyIdentifier o2 = (P11KeyIdentifier) o;
        if (keyId != null && o2.keyId != null)
        {
            return Arrays.equals(keyId, o2.keyId);
        }
        if (keyLabel != null && o2.keyLabel != null)
        {
            return keyLabel.equals(o2.keyLabel);
        }
        return false;
    }

    @Override
    public int compareTo(
            final P11KeyIdentifier o)
    {
        if (this == o)
        {
            return 0;
        }

        if (keyLabel == null)
        {
            return (o.keyLabel == null)
                    ? 0
                    : 1;
        }
        else
        {
            return (o.keyLabel == null)
                    ? -1
                    : keyLabel.compareTo(o.keyLabel);
        }
    }

}
