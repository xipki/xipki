/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.store;

import java.util.ArrayList;
import java.util.List;

import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class CertBasedIdentityStore
{
    private final String table;
    private final List<CertBasedIdentityEntry> entries;
    private int nextFreeId;

    CertBasedIdentityStore(String table, List<CertBasedIdentityEntry> entries)
    {
        this.table = table;
        this.entries = new ArrayList<>(entries.size());

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

    synchronized Integer getCaIdForSubject(String subject)
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
