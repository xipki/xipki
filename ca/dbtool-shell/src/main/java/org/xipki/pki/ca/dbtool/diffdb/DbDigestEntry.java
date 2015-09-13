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

package org.xipki.pki.ca.dbtool.diffdb;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 */

public class DbDigestEntry
{
    private final long serialNumber;
    private final boolean revoked;
    private final Integer revReason;
    private final Long revTime;
    private final Long revInvTime;
    private final String base64Sha1;

    public DbDigestEntry(
            final long serialNumber,
            final boolean revoked,
            final Integer revReason,
            final Long revTime,
            final Long revInvTime,
            final String sha1Fp)
    {
        ParamUtil.assertNotBlank("sha1Fp", sha1Fp);

        if(sha1Fp.length() == 28)
        {
            this.base64Sha1 = sha1Fp;
        } else if(sha1Fp.length() == 40)
        {
            this.base64Sha1 = Base64.toBase64String(Hex.decode(sha1Fp));
        } else
        {
            throw new IllegalArgumentException("invalid sha1Fp '" + sha1Fp + "'");
        }
        if(revoked)
        {
            ParamUtil.assertNotNull("revReason", revReason);
            ParamUtil.assertNotNull("revTime", revTime);
        }

        this.serialNumber = serialNumber;
        this.revoked = revoked;
        this.revReason = revReason;
        this.revTime = revTime;
        this.revInvTime = revInvTime;
    }

    public static DbDigestEntry decode(
            final String encoded)
    {
        List<Integer> indexes = getIndexes(encoded);
        if(indexes.size() != 5)
        {
            throw new IllegalArgumentException("invalid DbDigestEntry: " + encoded);
        }

        String s = encoded.substring(0, indexes.get(0));
        Long serialNumber = Long.parseLong(s);

        int i = 0;
        String sha1Fp = encoded.substring(indexes.get(i) + 1, indexes.get(i + 1));

        i++;
        s = encoded.substring(indexes.get(i) + 1, indexes.get(i + 1));
        boolean revoked = "0".equals(s) == false;

        Integer revReason = null;
        Long revTime = null;
        Long revInvTime = null;
        if(revoked)
        {
            i++;
            s = encoded.substring(indexes.get(i) + 1, indexes.get(i + 1));
            revReason = Integer.parseInt(s);

            i++;
            s = encoded.substring(indexes.get(i) + 1, indexes.get(i + 1));
            revTime = Long.parseLong(s);

            i++;
            s = encoded.substring(indexes.get(i) + 1);
            if(s.length() != 0)
            {
                revInvTime = Long.parseLong(s);
            }
        }

        return new DbDigestEntry(serialNumber, revoked, revReason, revTime, revInvTime, sha1Fp);
    }

    public long getSerialNumber()
    {
        return serialNumber;
    }

    public boolean isRevoked()
    {
        return revoked;
    }

    public int getRevReason()
    {
        return revReason;
    }

    public Long getRevTime()
    {
        return revTime;
    }

    public Long getRevInvTime()
    {
        return revInvTime;
    }

    public String getBase64Sha1()
    {
        return base64Sha1;
    }

    @Override
    public String toString()
    {
        return getEncoded();
    }

    public String getEncodedOmitSeriaNumber()
    {
        return getEncoded(false);
    }

    public String getEncoded()
    {
        return getEncoded(true);
    }

    private String getEncoded(
            final boolean withSerialNumber)
    {
        StringBuilder sb = new StringBuilder();
        if(withSerialNumber)
        {
            sb.append(serialNumber).append(";");
        }
        sb.append(base64Sha1).append(";");
        sb.append(revoked
                ? "1"
                : "0").append(";");

        if(revReason != null)
        {
            sb.append(revReason);
        }
        sb.append(";");

        if(revTime != null)
        {
            sb.append(revTime);
        }
        sb.append(";");

        if(revInvTime != null)
        {
            sb.append(revInvTime);
        }

        return sb.toString();
    }

    public boolean contentEquals(
            final DbDigestEntry b)
    {
        if(b == null)
        {
            return false;
        }

        if(serialNumber != b.serialNumber)
        {
            return false;
        }

        if(revoked != b.revoked)
        {
            return false;
        }

        if(equals(revReason, b.revReason) == false)
        {
            return false;
        }

        if(equals(revTime, b.revTime) == false)
        {
            return false;
        }

        if(equals(revInvTime, b.revInvTime) == false)
        {
            return false;
        }

        if(equals(base64Sha1, b.base64Sha1) == false)
        {
            return false;
        }

        return true;
    }

    private static List<Integer> getIndexes(
            final String encoded)
    {
        List<Integer> ret = new ArrayList<>(6);
        for(int i = 0; i < encoded.length(); i++)
        {
            if(encoded.charAt(i) == ';')
            {
                ret.add(i);
            }
        }
        return ret;
    }

    private static boolean equals(
            final Object a,
            final Object b)
    {
        if(a == null)
        {
            return b == null;
        } else
        {
            return a.equals(b);
        }
    }

}
