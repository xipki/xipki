/*
 * Copyright 2014 xipki.org
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

package org.xipki.ca.server.store;

import java.util.ArrayList;
import java.util.List;

import org.xipki.security.common.ParamChecker;

class CertBasedIdentityStore
{
    private final String table;
    private final List<CertBasedIdentityEntry> entries;
    private int nextFreeId;

    CertBasedIdentityStore(String table, List<CertBasedIdentityEntry> entries)
    {
        this.table = table;
        this.entries = new ArrayList<CertBasedIdentityEntry>(entries.size());

        for(CertBasedIdentityEntry entry : entries)
        {
            addIdentityEntry(entry);
        }

        if(nextFreeId < 1)
        {
            nextFreeId = 1;
        }
    }

    synchronized void addIdentityEntry(CertBasedIdentityEntry entry)
    {
        ParamChecker.assertNotNull("entry", entry);

        for(CertBasedIdentityEntry existingEntry : entries)
        {
            if(existingEntry.getId() == entry.getId())
            {
                throw new IllegalArgumentException(table + " with the same id " + entry.getId() + " already available");
            }
        }

        if(nextFreeId <= entry.getId())
        {
            nextFreeId = entry.getId() + 1;
        }

        entries.add(entry);
    }

    synchronized Integer getIdForSubject(String subject)
    {
        for(CertBasedIdentityEntry entry : entries)
        {
            if(entry.getSubject().equals(subject))
            {
                return entry.getId();
            }
        }

        return null;
    }

    synchronized Integer getCaIdForSha1Fp(byte[] sha1Fp_cert)
    {
        for(CertBasedIdentityEntry entry : entries)
        {
            if(entry.matchSha1Fp(sha1Fp_cert))
            {
                return entry.getId();
            }
        }

        return null;
    }

    synchronized Integer getCaIdForCert(byte[] encodedCert)
    {
        for(CertBasedIdentityEntry entry : entries)
        {
            if(entry.matchCert(encodedCert))
            {
                return entry.getId();
            }
        }

        return null;
    }

    synchronized int getNextFreeId()
    {
        return nextFreeId++;
    }

    String getTable()
    {
        return table;
    }
}
