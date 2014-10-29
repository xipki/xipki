/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.store;

import java.util.ArrayList;
import java.util.List;

import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class CertBasedIdentityStore
{
    private final String table;
    private final List<CertBasedIdentityEntry> entries;

    CertBasedIdentityStore(String table, List<CertBasedIdentityEntry> entries)
    {
        this.table = table;
        this.entries = new ArrayList<>(entries.size());

        for(CertBasedIdentityEntry entry : entries)
        {
            addIdentityEntry(entry);
        }
    }

    void addIdentityEntry(CertBasedIdentityEntry entry)
    {
        ParamChecker.assertNotNull("entry", entry);

        for(CertBasedIdentityEntry existingEntry : entries)
        {
            if(existingEntry.getId() == entry.getId())
            {
                throw new IllegalArgumentException(table + " with the same id " + entry.getId() + " already available");
            }
        }

        entries.add(entry);
    }

    Integer getCaIdForSubject(String subject)
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

    Integer getCaIdForSha1Fp(byte[] sha1Fp_cert)
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

    Integer getCaIdForCert(byte[] encodedCert)
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

    String getTable()
    {
        return table;
    }
}
