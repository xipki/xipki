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

package org.xipki.commons.pkcs11proxy.client.impl;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.xipki.commons.security.api.BadAsn1ObjectException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class Asn1Util {

    private static final BigInteger MAX_BYTE = BigInteger.valueOf(Byte.MAX_VALUE);

    private static final BigInteger MIN_BYTE = BigInteger.valueOf(Byte.MIN_VALUE);

    private static final BigInteger MAX_INT = BigInteger.valueOf(Integer.MAX_VALUE);

    private static final BigInteger MIN_INT = BigInteger.valueOf(Integer.MIN_VALUE);

    private Asn1Util() {
    }

    public static byte[] getBytes(
            final ASN1Encodable obj,
            final String desc)
    throws BadAsn1ObjectException {
        if (!(obj instanceof ASN1OctetString)) {
            throw new BadAsn1ObjectException(desc + " is not an octet string");
        }

        return ((ASN1OctetString) obj).getOctets();
    }

    public static boolean getBoolean(
            final ASN1Encodable obj,
            final String desc)
    throws BadAsn1ObjectException {
        if (!(obj instanceof ASN1Boolean)) {
            throw new BadAsn1ObjectException(desc + " is not a boolean");
        }
        return ((ASN1Boolean) obj).isTrue();
    }

    public static byte getByte(
            final ASN1Encodable obj,
            final String desc)
    throws BadAsn1ObjectException {
        if (!(obj instanceof ASN1Integer)) {
            throw new BadAsn1ObjectException(desc + " is not an integer");
        }

        BigInteger bi = ((ASN1Integer) obj).getValue();
        if (bi.compareTo(MAX_BYTE) > 0 || bi.compareTo(MIN_BYTE) < 0) {
            throw new BadAsn1ObjectException(desc + " is not in the range of byte");
        }
        return bi.byteValue();
    }

    public static int getInt(
            final ASN1Encodable obj,
            final String desc)
    throws BadAsn1ObjectException {
        if (!(obj instanceof ASN1Integer)) {
            throw new BadAsn1ObjectException(desc + " is not an integer");
        }

        BigInteger bi = ((ASN1Integer) obj).getValue();
        if (bi.compareTo(MAX_INT) > 0 || bi.compareTo(MIN_INT) < 0) {
            throw new BadAsn1ObjectException(desc + " is not in the range of integer");
        }
        return bi.intValue();
    }

    public static String getString(
            final ASN1Encodable obj,
            final String desc)
    throws BadAsn1ObjectException {
        if (!(obj instanceof ASN1String)) {
            throw new BadAsn1ObjectException(desc + " is not a string");
        }

        return ((ASN1String) obj).getString();
    }

    public static void assertSequenceLength(
            final ASN1Sequence seq,
            final int size,
            final String desc)
    throws BadAsn1ObjectException {
        final int n = seq.size();
        if (n != size) {
            StringBuilder sb = new StringBuilder(100);
            sb.append("wrong number of elements in sequence");
            if (desc != null && !desc.isEmpty()) {
                sb.append("'").append(desc).append("'");
            }
            sb.append(", is '").append(n).append("'");
            sb.append(", but expected '").append(size).append("'");

            throw new BadAsn1ObjectException(sb.toString());
        }
    }

}
