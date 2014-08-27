/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11.iaik;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11CryptServiceFactory;
import org.xipki.security.api.p11.P11ModuleConf;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class IaikP11CryptServiceFactory implements P11CryptServiceFactory
{
    private String defaultModuleName;
    private Map<String, P11ModuleConf> moduleConfs;

    @Override
    public void init(String defaultModuleName, Collection<P11ModuleConf> moduleConfs)
    {
        ParamChecker.assertNotEmpty("defaultModuleName", defaultModuleName);
        this.defaultModuleName = defaultModuleName;
        if(moduleConfs == null || moduleConfs.isEmpty())
        {
            this.moduleConfs = null;
        }
        else
        {
            this.moduleConfs = new HashMap<>(moduleConfs.size());
            for(P11ModuleConf conf : moduleConfs)
            {
                this.moduleConfs.put(conf.getName(), conf);
            }
        }

        IaikP11ModulePool.getInstance().setDefaultModuleName(defaultModuleName);
    }

    @Override
    public P11CryptService createP11CryptService(String moduleName)
    throws SignerException
    {
        if(moduleConfs == null)
        {
            throw new IllegalStateException("please call init() first");
        }

        ParamChecker.assertNotNull("moduleName", moduleName);

        if(SecurityFactory.DEFAULT_P11MODULE_NAME.equals(moduleName))
        {
            moduleName = defaultModuleName;
        }

        P11ModuleConf conf = moduleConfs.get(moduleName.toLowerCase());
        if(conf == null)
        {
            throw new SignerException("PKCS#11 module " + moduleName + " is not defined");
        }

        return IaikP11CryptService.getInstance(conf);
    }

}
