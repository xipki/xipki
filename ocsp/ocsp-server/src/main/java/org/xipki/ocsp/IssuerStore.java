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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.xipki.security.common.HashAlgoType;

/**
 * @author Lijun Liao
 */

public class IssuerStore
{
    private final Set<Integer> ids;
    private final List<IssuerEntry> entries;

    public IssuerStore(List<IssuerEntry> entries)
    {
        this.entries = new ArrayList<>(entries.size());
        Set<Integer> ids = new HashSet<>(entries.size());

        for(IssuerEntry entry : entries)
        {
            for(IssuerEntry existingEntry : this.entries)
            {
                if(existingEntry.getId() == entry.getId())
                {
                    throw new IllegalArgumentException(
                            "issuer with the same id " + entry.getId() + " already available");
                }
            }
            this.entries.add(entry);
            ids.add(entry.getId());
        }

        this.ids = Collections.unmodifiableSet(ids);
    }

    public Set<Integer> getIds()
    {
        return ids;
    }

    public Integer getIssuerIdForFp(HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash)
    {
        IssuerEntry issuerEntry = getIssuerForFp(hashAlgo, issuerNameHash, issuerKeyHash);
        return issuerEntry == null ? null : issuerEntry.getId();
    }

    public IssuerEntry getIssuerForId(int id)
    {
        for(IssuerEntry entry : entries)
        {
            if(entry.getId() == id)
            {
                return entry;
            }
        }

        return null;
    }

    public IssuerEntry getIssuerForFp( HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash)
    {
        for(IssuerEntry entry : entries)
        {
            if(entry.matchHash(hashAlgo, issuerNameHash, issuerKeyHash))
            {
                return entry;
            }
        }

        return null;
    }

}
