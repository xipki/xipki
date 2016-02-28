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

package org.xipki.pki.ca.api.profile;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertValidity implements Comparable<CertValidity>, Serializable {

    public enum Unit {

        YEAR("y"),
        DAY("d"),
        HOUR("h");

        private String suffix;

        Unit(
                String suffix) {
            this.suffix = suffix;
        }

        public String getSuffix() {
            return suffix;
        }

    } // enum Unit

    private static final long serialVersionUID = 1917871166917453960L;

    private static final long SECOND = 1000L;

    private static final long HOUR = 60L * 60 * SECOND;

    private static final long DAY = 24L * HOUR;

    private static final TimeZone TIMEZONE_UTC = TimeZone.getTimeZone("UTC");

    private final int validity;
    private final Unit unit;

    public CertValidity(
            final int validity,
            final Unit unit) {
        if (validity < 1) {
            throw new IllegalArgumentException("validity could not be less than 1");
        }
        ParamUtil.assertNotNull("unit", unit);
        this.validity = validity;
        this.unit = unit;
    }

    public static CertValidity getInstance(
            final String validityS) {
        ParamUtil.assertNotBlank("validityS", validityS);
        final int len = validityS.length();
        final char suffix = validityS.charAt(len - 1);
        Unit unit;
        String numValdityS;
        if (suffix == 'y' || suffix == 'Y') {
            unit = Unit.YEAR;
            numValdityS = validityS.substring(0, len - 1);
        } else if (suffix == 'd' || suffix == 'D') {
            unit = Unit.DAY;
            numValdityS = validityS.substring(0, len - 1);
        } else if (suffix == 'h' || suffix == 'H') {
            unit = Unit.HOUR;
            numValdityS = validityS.substring(0, len - 1);
        } else if (suffix >= '0' && suffix <= '9') {
            unit = Unit.DAY;
            numValdityS = validityS;
        } else {
            throw new IllegalArgumentException(String.format(
                    "invalid validityS: %s", validityS));
        }

        int validity;
        try {
            validity = Integer.parseInt(numValdityS);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException(String.format(
                    "invalid validityS: %s", validityS));
        }
        return new CertValidity(validity, unit);
    } // method getInstance

    public int getValidity() {
        return validity;
    }

    public Unit getUnit() {
        return unit;
    }

    public Date add(
            final Date referenceDate) {
        switch (unit) {
        case HOUR:
            return new Date(referenceDate.getTime() + HOUR - SECOND);
        case DAY:
            return new Date(referenceDate.getTime() + DAY - SECOND);
        case YEAR:
            Calendar cal = Calendar.getInstance(TIMEZONE_UTC);
            cal.setTime(referenceDate);
            cal.add(Calendar.YEAR, validity);
            cal.add(Calendar.SECOND, -1);

            int month = cal.get(Calendar.MONTH);
            // February
            if (month == 1) {
                int day = cal.get(Calendar.DAY_OF_MONTH);
                if (day > 28) {
                    int year = cal.get(Calendar.YEAR);
                    if (isLeapYear(year)) {
                        day = 29;
                    } else {
                        day = 28;
                    }
                }
            }

            return cal.getTime();
        default:
            throw new RuntimeException(String.format(
                    "should not reach here, unknown CertValidity.Unit %s", unit));
        }
    } // method add

    private int getApproxHours() {
        switch (unit) {
        case HOUR:
            return validity;
        case DAY:
            return 24 * validity;
        case YEAR:
            return (365 * validity + validity / 4) * 24;
        default:
            throw new RuntimeException(String.format(
                    "should not reach here, unknown CertValidity.Unit %s", unit));
        }
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    @Override
    public int compareTo(
            final CertValidity obj) {
        if (unit == obj.unit) {
            if (validity == obj.validity) {
                return 0;
            }

            return (validity < obj.validity)
                    ? -1
                    : 1;
        } else {
            int thisHours = getApproxHours();
            int thatHours = obj.getApproxHours();
            if (thisHours == thatHours) {
                return 0;
            } else {
                return (thisHours < thatHours)
                        ? -1
                        : 1;
            }
        }
    }

    @Override
    public boolean equals(
            final Object obj) {
        if (!(obj instanceof CertValidity)) {
            return false;
        }

        CertValidity other = (CertValidity) obj;
        return unit == other.unit && validity == other.validity;
    }

    @Override
    public String toString() {
        switch (unit) {
        case HOUR:
            return validity + "h";
        case DAY:
            return validity + "d";
        case YEAR:
            return validity + "y";
        default:
            throw new RuntimeException(String.format(
                    "should not reach here, unknown CertValidity.Unit %s", unit));
        }
    }

    private static boolean isLeapYear(
            final int year) {
        if (year % 4 != 0) {
            return false;
        } else if (year % 100 != 0) {
            return true;
        } else {
            return year % 400 == 0;
        }
    }

}
