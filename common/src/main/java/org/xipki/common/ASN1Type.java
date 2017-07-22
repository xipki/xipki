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

package org.xipki.ocsp.server.impl.type;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

// CHECKSTYLE:SKIP
public abstract class ASN1Type {

    public abstract int encodedLength();

    public abstract int write(byte[] out, int offset);

    protected static int getHeaderLen(int bodyLen) {
        if (bodyLen <= 0x7F) {
            return 2;
        } else if (bodyLen <= 0xFF) {
            return 3;
        } else if (bodyLen <= 0xFFFF) {
            return 4;
        } else if (bodyLen <= 0xFFFFFF) {
            return 5;
        } else {
            return 6;
        }
    }

    protected static int writeHeader(final int tag, final int bodyLen,
            final byte[] out, final int offset) {
        int idx = offset;
        out[idx++] = (byte) tag;
        if (bodyLen <= 0x7F) {
            out[idx++] = (byte) bodyLen;
        } else if (bodyLen <= 0xFF) {
            out[idx++] = (byte) 0x81;
            out[idx++] = (byte) bodyLen;
        } else if (bodyLen <= 0xFFFF) {
            out[idx++] = (byte) 0x82;
            out[idx++] = (byte) (bodyLen >> 8);
            out[idx++] = (byte) (0xFF & bodyLen);
        } else if (bodyLen <= 0xFFFFFF) {
            out[idx++] = (byte) 0x83;
            out[idx++] = (byte) (0xFF & (bodyLen >> 16));
            out[idx++] = (byte) (0xFF & (bodyLen >> 8));
            out[idx++] = (byte) (0xFF & bodyLen);
        } else {
            out[idx++] = (byte) 0x84;
            out[idx++] = (byte) (0xFF & (bodyLen >> 24));
            out[idx++] = (byte) (0xFF & (bodyLen >> 16));
            out[idx++] = (byte) (0xFF & (bodyLen >> 8));
            out[idx++] = (byte) (0xFF & bodyLen);
        }
        return idx - offset;
    }

    protected static int writeGeneralizedTime(final Date time,
            final byte[] out, final int offset) {
        OffsetDateTime offsetTime = time.toInstant().atOffset(ZoneOffset.UTC);
        int idx = offset;
        out[idx++] = 0x18;
        out[idx++] = 15;
        // yyyyMMddhhmmssZ
        // year
        int year = offsetTime.getYear();
        out[idx++] = (byte) (0x30 + year / 1000);
        out[idx++] = (byte) (0x30 + year / 100 % 10);
        out[idx++] = (byte) (0x30 + year / 10 % 10);
        out[idx++] = (byte) (0x30 + year % 10);
        // month
        int month = offsetTime.getMonthValue();
        out[idx++] = (byte) (0x30 + month / 10);
        out[idx++] = (byte) (0x30 + month % 10);
        // day
        int day = offsetTime.getDayOfMonth();
        out[idx++] = (byte) (0x30 + day / 10);
        out[idx++] = (byte) (0x30 + day % 10);
        // hour
        int hour = offsetTime.getHour();
        out[idx++] = (byte) (0x30 + hour / 10);
        out[idx++] = (byte) (0x30 + hour % 10);
        // minute
        int minute = offsetTime.getMinute();
        out[idx++] = (byte) (0x30 + minute / 10);
        out[idx++] = (byte) (0x30 + minute % 10);
        // second
        int second = offsetTime.getSecond();
        out[idx++] = (byte) (0x30 + second / 10);
        out[idx++] = (byte) (0x30 + second % 10);
        out[idx++] = 'Z';
        return idx - offset;
    }

    protected static int arraycopy(byte[] src, byte[] dest, int destPos) {
        final int length = src.length;
        System.arraycopy(src, 0, dest, destPos, length);
        return length;
    }

}
