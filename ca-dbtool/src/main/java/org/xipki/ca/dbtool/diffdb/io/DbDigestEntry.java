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
