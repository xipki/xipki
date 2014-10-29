/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.provider;

import java.security.Security;

import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public class XiPKIProviderRegister
{
    public void regist()
    {
        if(Security.getProperty(XiPKIProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new XiPKIProvider());
        }
    }

    public void unregist()
    {
        if(Security.getProperty(XiPKIProvider.PROVIDER_NAME) != null)
        {
            Security.removeProvider(XiPKIProvider.PROVIDER_NAME);
        }
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        XiPKIKeyStoreSpi.setSecurityFactory(securityFactory);
    }

}
