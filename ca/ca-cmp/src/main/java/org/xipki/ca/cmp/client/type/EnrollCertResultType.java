/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.cmp.client.type;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class EnrollCertResultType implements CmpResultType
{
    private List<CMPCertificate> cACertificates;
    private List<ResultEntryType> resultEntries;

    public EnrollCertResultType()
    {
    }

    public void addCACertificate(CMPCertificate cACertificate)
    {
        if(cACertificates == null)
        {
            cACertificates = new ArrayList<>(1);
        }
        cACertificates.add(cACertificate);
    }

    public void addResultEntry(ResultEntryType resultEntry)
    {
        ParamChecker.assertNotNull("resultEntry", resultEntry);

        if((resultEntry instanceof EnrollCertResultEntryType ||
                resultEntry instanceof ErrorResultEntryType) == false)
        {
            throw new IllegalArgumentException("Unaccepted parameter of class " + resultEntry.getClass().getName());
        }

        if(resultEntries == null)
        {
            resultEntries = new ArrayList<>(1);
        }

        resultEntries.add(resultEntry);
    }

    public List<CMPCertificate> getCACertificates()
    {
        return cACertificates;
    }

    public List<ResultEntryType> getResultEntries()
    {
        return resultEntries;
    }

}
