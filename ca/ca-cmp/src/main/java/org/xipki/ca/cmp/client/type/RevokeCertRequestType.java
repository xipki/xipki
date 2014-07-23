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

public class RevokeCertRequestType
{
    private final List<RevokeCertRequestEntryType> requestEntries = new LinkedList<>();

    public boolean addRequestEntry(RevokeCertRequestEntryType requestEntry)
    {
        for(RevokeCertRequestEntryType re : requestEntries)
        {
            if(re.getId().equals(requestEntry.getId()))
            {
                return false;
            }
        }

        requestEntries.add(requestEntry);
        return true;
    }

    public List<RevokeCertRequestEntryType> getRequestEntries()
    {
        return Collections.unmodifiableList(requestEntries);
    }
}
