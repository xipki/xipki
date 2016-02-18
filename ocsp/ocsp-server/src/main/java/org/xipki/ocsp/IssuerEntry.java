/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
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

package org.xipki.ocsp;

import java.util.Date;
import java.util.Map;

import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class IssuerEntry
{
    private final int id;
    private final Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap;
    private final Date caNotBefore;

    private boolean revoked;
    private Date revocationTime;

    public IssuerEntry(int id, Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap, Date caNotBefore)
    {
        ParamChecker.assertNotEmpty("issuerHashMap", issuerHashMap);
        ParamChecker.assertNotNull("caNotBefore", caNotBefore);

        this.id = id;
        this.issuerHashMap = issuerHashMap;
        this.caNotBefore = caNotBefore;
    }

    public int getId()
    {
        return id;
    }

    public boolean matchHash(HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash)
    {
        IssuerHashNameAndKey issuerHash = issuerHashMap.get(hashAlgo);
        return issuerHash == null ? false : issuerHash.match(hashAlgo, issuerNameHash, issuerKeyHash);
    }

    public boolean isRevoked()
    {
        return revoked;
    }

    public void setRevoked(boolean revoked)
    {
        this.revoked = revoked;
    }

    public Date getRevocationTime()
    {
        return revocationTime;
    }

    public void setRevocationTime(Date revocationTime)
    {
        this.revocationTime = revocationTime;
    }

    public Date getCaNotBefore()
    {
        return caNotBefore;
    }
}
