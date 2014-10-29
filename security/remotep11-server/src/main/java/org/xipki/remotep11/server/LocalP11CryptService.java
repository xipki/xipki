/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.remotep11.server;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.p11.P11CryptService;

/**
 * @author Lijun Liao
 */

public class LocalP11CryptService
{
    private static final Logger LOG = LoggerFactory.getLogger(LocalP11CryptService.class);

    public static final int version = 1;

    private SecurityFactory securityFactory;
    private P11CryptService p11CryptService;

    public LocalP11CryptService()
    {
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    private boolean initialized = false;
    public void init()
    throws Exception
    {
        if(initialized)
        {
            return;
        }

        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try
        {
            if(securityFactory == null)
            {
                throw new IllegalStateException("securityFactory is not configured");
            }

            this.p11CryptService = securityFactory.getP11CryptService(SecurityFactory.DEFAULT_P11MODULE_NAME);
            initialized = true;
        }catch(Exception e)
        {
            LOG.error("Exception thrown. {}: {}", e.getClass().getName(), e.getMessage());
            LOG.debug("Exception thrown", e);
            throw e;
        }
    }

    public P11CryptService getP11CryptService()
    {
        return p11CryptService;
    }

    public int getVersion()
    {
        return version;
    }

}
