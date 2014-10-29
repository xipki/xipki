/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.p11;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ParamChecker;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11Control;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11CryptServiceFactory;
import org.xipki.security.api.p11.P11ModuleConf;
import org.xipki.security.api.p11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 */

public class RemoteP11CryptServiceFactory implements P11CryptServiceFactory
{
    private static final Logger LOG = LoggerFactory.getLogger(RemoteP11CryptServiceFactory.class);

    private P11Control p11Control;

    @Override
    public void init(P11Control p11Control)
    {
        ParamChecker.assertNotNull("p11Control", p11Control);
        this.p11Control = p11Control;
    }

    private final Map<String, RemoteP11CryptService> services = new HashMap<>();

    @Override
    public P11CryptService createP11CryptService(String moduleName)
    throws SignerException
    {
        ParamChecker.assertNotNull("moduleName", moduleName);
        if(p11Control == null)
        {
            throw new IllegalStateException("please call init() first");
        }

        if(SecurityFactory.DEFAULT_P11MODULE_NAME.equals(moduleName))
        {
            moduleName = p11Control.getDefaultModuleName();
        }

        P11ModuleConf moduleConf = p11Control.getModuleConf(moduleName);
        if(moduleConf == null)
        {
            throw new SignerException("PKCS#11 module " + moduleName + " is not defined");
        }

        synchronized (services)
        {
            RemoteP11CryptService service = services.get(moduleName);
            if(service == null)
            {
                try
                {
                    service = new DefaultRemoteP11CryptService(moduleConf);
                    String url = ((DefaultRemoteP11CryptService) service).getServerUrl();
                    logServiceInfo(url, service);
                    services.put(moduleConf.getName(), service);
                }catch(Exception e)
                {
                    LOG.error("Could not createP11CryptService: {}", e.getMessage());
                    LOG.debug("Could not createP11CryptService", e);
                    throw new SignerException(e.getMessage(), e);
                }
            }

            return service;
        }
    }

    private static void logServiceInfo(String url, RemoteP11CryptService service)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("Initialized RemoteP11CryptService (url=").append(url).append(")\n");

        P11SlotIdentifier[] slotIds;
        try
        {
            slotIds = service.getSlotIdentifiers();
        } catch (SignerException e)
        {
            LOG.warn("RemoteP11CryptService.getSlotIdentifiers(); SignerException: "
                    + "url={}, message={}",
                    url, e.getMessage());
            LOG.debug("RemoteP11CryptService.getSlotIdentifiers(); SignerException", e);
            return;
        }

        if(slotIds == null || slotIds.length == 0)
        {
            sb.append("\tNo slot is available");
            LOG.warn("{}", sb);
            return;
        }

        for(P11SlotIdentifier slotId : slotIds)
        {
            String[] keyLabels;
            try
            {
                keyLabels = service.getKeyLabels(slotId);
            } catch (SignerException e)
            {
                LOG.warn("RemoteP11CryptService.getKeyLabels(); SignerException: "
                        + "url={}, slot={}, message={}",
                        new Object[]{url, slotId, e.getMessage()});
                LOG.debug("RemoteP11CryptService.getKeyLabels(); SignerException", e);
                continue;
            }

            if(keyLabels != null && keyLabels.length > 0)
            {
                for(String keyLabel : keyLabels)
                {
                    sb.append("\t(slot ").append(slotId);
                    sb.append(", label=").append(keyLabel).append(")\n");
                }
            }
        }

        LOG.info("{}", sb);
    }

}
