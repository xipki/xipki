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

package org.xipki.common;

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

    public static int getLen(int bodyLen) {
        return getHeaderLen(bodyLen) + bodyLen;
    }

    public static int getHeaderLen(int bodyLen) {
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

    public static int writeHeader(final byte tag, final int bodyLen,
            final byte[] out, final int offset) {
        int idx = offset;
        out[idx++] = tag;
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

    public static int writeGeneralizedTime(final Date time,
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

    public static int arraycopy(byte[] src, byte[] dest, int destPos) {
        final int length = src.length;
        System.arraycopy(src, 0, dest, destPos, length);
        return length;
    }

}
