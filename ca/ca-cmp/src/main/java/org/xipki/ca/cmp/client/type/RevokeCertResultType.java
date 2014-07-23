/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.client.type;

import java.util.ArrayList;
import java.util.List;

import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class RevokeCertResultType implements CmpResultType
{
    private List<ResultEntryType> resultEntries;

    public List<ResultEntryType> getResultEntries()
    {
        return resultEntries;
    }

    public void addResultEntry(ResultEntryType resultEntry)
    {
        ParamChecker.assertNotNull("resultEntry", resultEntry);

        if((resultEntry instanceof RevokeCertResultEntryType || resultEntry instanceof ErrorResultEntryType) == false)
        {
            throw new IllegalArgumentException("Unaccepted parameter of class " + resultEntry.getClass().getName());
        }

        if(resultEntries == null)
        {
            resultEntries = new ArrayList<>(1);
        }

        resultEntries.add(resultEntry);
    }

}
