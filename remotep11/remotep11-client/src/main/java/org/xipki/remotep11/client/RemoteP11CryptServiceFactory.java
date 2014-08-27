/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.remotep11.client;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11CryptServiceFactory;
import org.xipki.security.api.p11.P11ModuleConf;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class RemoteP11CryptServiceFactory implements P11CryptServiceFactory
{
    private static final Logger LOG = LoggerFactory.getLogger(RemoteP11CryptServiceFactory.class);

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
    }

    private final Map<String, RemoteP11CryptService> services = new HashMap<>();

    @Override
    public P11CryptService createP11CryptService(String moduleName)
    throws SignerException
    {
        ParamChecker.assertNotNull("moduleName", moduleName);
        if(SecurityFactory.DEFAULT_P11MODULE_NAME.equals(moduleName))
        {
            moduleName = defaultModuleName;
        }

        if(moduleConfs == null)
        {
            throw new IllegalStateException("please call init() first");
        }

        P11ModuleConf moduleConf = moduleConfs.get(moduleName.toLowerCase());
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
                    CmpUtf8Pairs conf = new CmpUtf8Pairs(moduleConf.getNativeLibrary());
                    String url = conf.getValue("url");
                    if(url == null || url.isEmpty())
                    {
                        throw new IllegalArgumentException("url is not specified");
                    }

                    service = new DefaultRemoteP11CryptService(url);
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
