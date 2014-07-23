/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.certprofile;

import java.util.List;

import org.xipki.ca.api.profile.ExtensionTuple;
import org.xipki.security.common.EnvironmentParameterResolver;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

class ExtensionTupleOptions
{
    private final List<ExtensionTupleOption> options;

    public ExtensionTupleOptions(List<ExtensionTupleOption> options)
    {
        ParamChecker.assertNotEmpty("options", options);
        this.options = options;
    }

    public ExtensionTuple getExtensionTuple(EnvironmentParameterResolver pr)
    {
        for(ExtensionTupleOption o : options)
        {
            Condition c = o.getCondition();
            if(c == null || c.satisfy(pr))
            {
                return o.getExtensionTuple();
            }
        }

        return null;
    }

}
