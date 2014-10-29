/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11.iaik;

import org.xipki.common.ParamChecker;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11Control;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11CryptServiceFactory;
import org.xipki.security.api.p11.P11ModuleConf;

/**
 * @author Lijun Liao
 */

public class IaikP11CryptServiceFactory implements P11CryptServiceFactory
{
    private P11Control p11Control;

    @Override
    public void init(P11Control p11Control)
    {
        ParamChecker.assertNotNull("p11Control", p11Control);
        this.p11Control = p11Control;
        IaikP11ModulePool.getInstance().setDefaultModuleName(p11Control.getDefaultModuleName());
    }

    @Override
    public P11CryptService createP11CryptService(String moduleName)
    throws SignerException
    {
        if(p11Control == null)
        {
            throw new IllegalStateException("please call init() first");
        }

        ParamChecker.assertNotNull("moduleName", moduleName);

        if(SecurityFactory.DEFAULT_P11MODULE_NAME.equals(moduleName))
        {
            moduleName = p11Control.getDefaultModuleName();
        }

        P11ModuleConf conf = p11Control.getModuleConf(moduleName);
        if(conf == null)
        {
            throw new SignerException("PKCS#11 module " + moduleName + " is not defined");
        }

        return IaikP11CryptService.getInstance(conf);
    }

}
