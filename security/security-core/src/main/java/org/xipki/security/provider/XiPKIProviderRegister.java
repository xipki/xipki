/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.provider;

import java.security.Security;

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

    public void setPkcs11Module(String pkcs11Module)
    {
        XiPKIKeyStoreSpi.setDefaultPkcs11Module(pkcs11Module);
    }

    public void setPkcs11Provider(String pkcs11Provider)
    {
        XiPKIKeyStoreSpi.setDefaultPkcs11Provider(pkcs11Provider);
    }

}
