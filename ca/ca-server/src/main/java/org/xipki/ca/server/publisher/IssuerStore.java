/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.publisher;

import java.util.ArrayList;
import java.util.List;

import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class IssuerStore
{
    private final List<IssuerEntry> entries;

    IssuerStore( List<IssuerEntry> entries)
    {
        this.entries = new ArrayList<>(entries.size());

        for(IssuerEntry entry : entries)
        {
            addIdentityEntry(entry);
        }
    }

    void addIdentityEntry(IssuerEntry entry)
    {
        ParamChecker.assertNotNull("entry", entry);

        for(IssuerEntry existingEntry : entries)
        {
            if(existingEntry.getId() == entry.getId())
            {
                throw new IllegalArgumentException("issuer with the same id " + entry.getId() + " already available");
            }
        }

        entries.add(entry);
    }

    Integer getIdForSubject(String subject)
    {
        for(IssuerEntry entry : entries)
        {
            if(entry.getSubject().equals(subject))
            {
                return entry.getId();
            }
        }

        return null;
    }

    Integer getIdForSha1Fp(byte[] sha1Fp_cert)
    {
        for(IssuerEntry entry : entries)
        {
            if(entry.matchSha1Fp(sha1Fp_cert))
            {
                return entry.getId();
            }
        }

        return null;
    }

    Integer getIdForCert(byte[] encodedCert)
    {
        for(IssuerEntry entry : entries)
        {
            if(entry.matchCert(encodedCert))
            {
                return entry.getId();
            }
        }

        return null;
    }
}
