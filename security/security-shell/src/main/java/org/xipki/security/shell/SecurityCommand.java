/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import org.xipki.console.karaf.XipkiOsgiCommandSupport;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.p11.iaik.IaikExtendedModule;
import org.xipki.security.p11.iaik.IaikP11CryptServiceFactory;
import org.xipki.security.p11.iaik.IaikP11ModulePool;

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

    protected IaikExtendedModule getModule(String moduleName)
    throws SignerException
    {
        // this call initialize the IaikExtendedModule
        P11CryptService p11CryptService = securityFactory.getP11CryptService(moduleName);
        if(p11CryptService == null)
        {
            throw new SignerException("Could not initialize P11CryptService " + moduleName);
        }

        // the returned object could not be null
        IaikExtendedModule module = IaikP11ModulePool.getInstance().getModule(moduleName);
        if(module == null)
        {
           throw new SignerException("P11KeypairGenerator only works with P11CryptServiceFactory " +
                   IaikP11CryptServiceFactory.class.getName());
        }
        return module;
    }

}
