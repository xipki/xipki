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

package org.xipki.ca.server.certprofile;

import java.util.List;
import java.util.regex.Pattern;

import org.xipki.security.common.EnvironmentParameterResolver;

/**
 * @author Lijun Liao
 */

class SubjectDNOption
{
    private final List<AddText> addprefixes;
    private final List<AddText> addsufixes;
    private final Pattern pattern;

    public SubjectDNOption(List<AddText> addprefixes, List<AddText> addsufixes, Pattern pattern)
    {
        this.addprefixes = addprefixes;
        this.addsufixes = addsufixes;
        this.pattern = pattern;
    }

    public AddText getAddprefix(EnvironmentParameterResolver pr)
    {
        return getAddText(addprefixes, pr);
    }

    public AddText getAddsufix(EnvironmentParameterResolver pr)
    {
        return getAddText(addsufixes, pr);
    }

    private static AddText getAddText(List<AddText> list, EnvironmentParameterResolver pr)
    {
        if(list == null || list.isEmpty())
        {
            return null;
        }

        for(AddText e : list)
        {
            if(e.getCondition() == null)
            {
                return e;
            }

            Condition c = e.getCondition();

            if(c.satisfy(pr))
            {
                return e;
            }
        }

        return null;
    }

    public Pattern getPattern()
    {
        return pattern;
    }

}
