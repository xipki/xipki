/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.client.type;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Lijun Liao
 */

public class UnrevokeOrRemoveCertRequestType
{
    private final List<IssuerSerialEntryType> requestEntries = new LinkedList<>();

    public boolean addRequestEntry(IssuerSerialEntryType requestEntry)
    {
        for(IssuerSerialEntryType re : requestEntries)
        {
            if(re.getId().equals(requestEntry.getId()))
            {
                return false;
            }
        }

        requestEntries.add(requestEntry);
        return true;
    }

    public List<IssuerSerialEntryType> getRequestEntries()
    {
        return Collections.unmodifiableList(requestEntries);
    }
}
