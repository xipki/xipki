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

package org.xipki.ca.dbtool.diffdb.io;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;
import org.xipki.common.util.Base64;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbDigestEntry {

    private final BigInteger serialNumber;

    private final boolean revoked;

    private final Integer revReason;

    private final Long revTime;

    private final Long revInvTime;

    private final String base64Sha1;

    public DbDigestEntry(final BigInteger serialNumber, final boolean revoked,
            final Integer revReason, final Long revTime, final Long revInvTime,
            final String sha1Fp) {
        ParamUtil.requireNonNull("sha1Fp", sha1Fp);
        if (revoked) {
            ParamUtil.requireNonNull("revReason", revReason);
            ParamUtil.requireNonNull("revTime", revTime);
        }

        if (sha1Fp.length() == 28) {
            this.base64Sha1 = sha1Fp;
        } else if (sha1Fp.length() == 40) {
            this.base64Sha1 = Base64.encodeToString(Hex.decode(sha1Fp));
        } else {
            throw new IllegalArgumentException("invalid sha1Fp '" + sha1Fp + "'");
        }

        this.serialNumber = serialNumber;
        this.revoked = revoked;
        this.revReason = revReason;
        this.revTime = revTime;
        this.revInvTime = revInvTime;
    }

    public BigInteger serialNumber() {
        return serialNumber;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public int revReason() {
        return revReason;
    }

    public Long revTime() {
        return revTime;
    }

    public Long revInvTime() {
        return revInvTime;
    }

    public String base64Sha1() {
        return base64Sha1;
    }

    @Override
    public String toString() {
        return encoded();
    }

    public String encodedOmitSeriaNumber() {
        return encoded(false);
    }

    public String encoded() {
        return encoded(true);
    }

    private String encoded(final boolean withSerialNumber) {
        StringBuilder sb = new StringBuilder();
        if (withSerialNumber) {
            sb.append(serialNumber.toString(16)).append(";");
        }
        sb.append(base64Sha1).append(";");
        sb.append(revoked ? "1" : "0").append(";");

        if (revReason != null) {
            sb.append(revReason);
        }
        sb.append(";");

        if (revTime != null) {
            sb.append(revTime);
        }
        sb.append(";");

        if (revInvTime != null) {
            sb.append(revInvTime);
        }

        return sb.toString();
    }

    public boolean contentEquals(final DbDigestEntry obj) {
        if (obj == null) {
            return false;
        }

        if (serialNumber != obj.serialNumber) {
            return false;
        }

        if (revoked != obj.revoked) {
            return false;
        }

        if (!equals(revReason, obj.revReason)) {
            return false;
        }

        if (!equals(revTime, obj.revTime)) {
            return false;
        }

        if (!equals(revInvTime, obj.revInvTime)) {
            return false;
        }

        if (!equals(base64Sha1, obj.base64Sha1)) {
            return false;
        }

        return true;
    } // method contentEquals

    public static DbDigestEntry decode(final String encoded) {
        ParamUtil.requireNonNull("encoded", encoded);

        List<Integer> indexes = getIndexes(encoded);
        if (indexes.size() != 5) {
            throw new IllegalArgumentException("invalid DbDigestEntry: " + encoded);
        }

        String str = encoded.substring(0, indexes.get(0));
        BigInteger serialNumber = new BigInteger(str, 16);

        String sha1Fp = encoded.substring(indexes.get(0) + 1, indexes.get(1));

        int idx = 1;
        str = encoded.substring(indexes.get(idx) + 1, indexes.get(idx + 1));
        boolean revoked = !"0".equals(str);

        Integer revReason = null;
        Long revTime = null;
        Long revInvTime = null;
        if (revoked) {
            idx++;
            str = encoded.substring(indexes.get(idx) + 1, indexes.get(idx + 1));
            revReason = Integer.parseInt(str);

            idx++;
            str = encoded.substring(indexes.get(idx) + 1, indexes.get(idx + 1));
            revTime = Long.parseLong(str);

            idx++;
            str = encoded.substring(indexes.get(idx) + 1);
            if (str.length() != 0) {
                revInvTime = Long.parseLong(str);
            }
        }

        return new DbDigestEntry(serialNumber, revoked, revReason, revTime, revInvTime, sha1Fp);
    } // method decode

    private static List<Integer> getIndexes(final String encoded) {
        List<Integer> ret = new ArrayList<>(6);
        for (int i = 0; i < encoded.length(); i++) {
            if (encoded.charAt(i) == ';') {
                ret.add(i);
            }
        }
        return ret;
    }

    private static boolean equals(final Object obj1, final Object obj2) {
        return (obj1 == null) ? (obj2 == null) : obj1.equals(obj2);
    }

}
