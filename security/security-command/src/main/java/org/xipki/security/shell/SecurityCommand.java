package org.xipki.security.shell;

import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.xipki.security.api.SecurityFactory;

public abstract class SecurityCommand extends OsgiCommandSupport {

    protected SecurityFactory securityFactory;

    public SecurityFactory getSecurityFactory()
    {
        return securityFactory;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }


}
