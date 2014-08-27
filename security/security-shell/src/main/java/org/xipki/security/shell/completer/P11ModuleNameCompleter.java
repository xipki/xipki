/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell.completer;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.xipki.console.karaf.DynamicEnumCompleter;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public class P11ModuleNameCompleter extends DynamicEnumCompleter
{
    private SecurityFactory securityFactory;

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    @Override
    protected Set<String> getEnums()
    {
        Set<String> names = securityFactory.getPkcs11ModuleNames();
        if(names == null | names.isEmpty())
        {
            return Collections.emptySet();
        }
        Set<String> ret = new HashSet<>(names);
        if(ret.contains(SecurityFactory.DEFAULT_P11MODULE_NAME) == false)
        {
            ret.add(SecurityFactory.DEFAULT_P11MODULE_NAME);
        }
        return ret;
    }

}
