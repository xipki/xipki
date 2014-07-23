/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import org.xipki.console.karaf.XipkiOsgiCommandSupport;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public abstract class SecurityCommand extends XipkiOsgiCommandSupport
{

    protected SecurityFactory securityFactory;

    public SecurityFactory getSecurityFactory()
    {
        return securityFactory;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    protected char[] readPasswordIfRequired(String password, Boolean readFromConsole)
    {
        if(password != null)
        {
            return password.toCharArray();
        }
        else
        {
            return isTrue(readFromConsole) ? readPassword() : null;
        }
    }

}
