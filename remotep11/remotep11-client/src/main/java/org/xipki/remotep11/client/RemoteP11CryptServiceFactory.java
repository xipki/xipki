/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.remotep11.client;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11CryptServiceFactory;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.common.CmpUtf8Pairs;

/**
 * @author Lijun Liao
 */

public class RemoteP11CryptServiceFactory implements P11CryptServiceFactory
{
    private static final Logger LOG = LoggerFactory.getLogger(RemoteP11CryptServiceFactory.class);

    private final Map<String, RemoteP11CryptService> services = new HashMap<>();

    @Override
    public P11CryptService createP11CryptService(String pkcs11Module, char[] password)
    throws SignerException
    {
        synchronized (services)
        {
            RemoteP11CryptService service = services.get(pkcs11Module);
            if(service == null)
            {
                try
                {
                    CmpUtf8Pairs conf = new CmpUtf8Pairs(pkcs11Module);
                    String url = conf.getValue("url");
                    if(url == null || url.isEmpty())
                    {
                        throw new IllegalArgumentException("url is not specified");
                    }

                    service = new DefaultRemoteP11CryptService(url);
                    logServiceInfo(url, service);
                    services.put(pkcs11Module, service);
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

    @Override
    public P11CryptService createP11CryptService(String pkcs11Module,
            char[] password, Set<Integer> includeSlotIndexes, Set<Integer> excludeSlotIndexes)
    throws SignerException
    {
        return createP11CryptService(pkcs11Module, password);
    }

}
