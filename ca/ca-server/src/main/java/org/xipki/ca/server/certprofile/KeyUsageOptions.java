/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

import java.util.List;
import java.util.Set;

import org.xipki.ca.api.profile.KeyUsage;
import org.xipki.common.EnvironmentParameterResolver;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class KeyUsageOptions
{
    private final List<KeyUsageOption> options;

    public KeyUsageOptions(List<KeyUsageOption> options)
    {
        ParamChecker.assertNotEmpty("options", options);
        this.options = options;
    }

    public Set<KeyUsage> getKeyusage(EnvironmentParameterResolver pr)
    {
        for(KeyUsageOption o : options)
        {
            Condition c = o.getCondition();
            if(c == null || c.satisfy(pr))
            {
                return o.getKeyusages();
            }
        }

        return null;
    }

}
