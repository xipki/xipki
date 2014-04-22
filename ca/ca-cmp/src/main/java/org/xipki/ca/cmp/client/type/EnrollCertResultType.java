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

package org.xipki.ca.cmp.client.type;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.xipki.security.common.ParamChecker;

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
            cACertificates = new ArrayList<CMPCertificate>(1);
        }
        cACertificates.add(cACertificate);
    }

    public void addResultEntry(ResultEntryType resultEntry)
    {
        ParamChecker.assertNotNull("resultEntry", resultEntry);

        if((resultEntry instanceof EnrollCertResultEntryType || resultEntry instanceof ErrorResultEntryType) == false)
        {
            throw new IllegalArgumentException("Unaccepted parameter of class " + resultEntry.getClass().getCanonicalName());
        }

        if(resultEntries == null)
        {
            resultEntries = new ArrayList<ResultEntryType>(1);
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
