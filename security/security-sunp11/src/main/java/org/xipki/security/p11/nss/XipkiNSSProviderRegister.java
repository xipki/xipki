/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11.nss;

import java.security.Security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.common.LogUtil;

/**
 * @author Lijun Liao
 */

public class XipkiNSSProviderRegister
{
    private static Logger LOG = LoggerFactory.getLogger(XipkiNSSProviderRegister.class);
    public void regist()
    {
        if(Security.getProvider(XipkiNSSProvider.PROVIDER_NAME) == null)
        {
            try
            {
                XipkiNSSProvider provider = new XipkiNSSProvider();
                Security.addProvider(provider);
            }catch(Throwable t)
            {
                final String message = "Could not add provider " + XipkiNSSProvider.PROVIDER_NAME;
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
                }
                LOG.debug(message, t);
            }
        }
    }

    public void unregist()
    {
        if(Security.getProperty(XipkiNSSProvider.PROVIDER_NAME) != null)
        {
            Security.removeProvider(XipkiNSSProvider.PROVIDER_NAME);
        }
    }

}
