/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
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
