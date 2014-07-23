/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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
