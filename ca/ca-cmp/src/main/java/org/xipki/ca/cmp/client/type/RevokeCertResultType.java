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
