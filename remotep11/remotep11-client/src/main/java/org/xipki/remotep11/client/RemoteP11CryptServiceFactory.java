/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.remotep11.client;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.P11CryptServiceFactory;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.CmpUtf8Pairs;

public class RemoteP11CryptServiceFactory implements P11CryptServiceFactory
{
    private static final Logger LOG = LoggerFactory.getLogger(RemoteP11CryptServiceFactory.class);

    private final Map<String, RemoteP11CryptService> services = new HashMap<String, RemoteP11CryptService>();

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

                    String user = conf.getValue("user");

                    String pwd = conf.getValue("password");
                    if(pwd != null)
                    {
                        password = pwd.toCharArray();
                    }

                    service = new DefaultRemoteP11CryptService(url, user, password);
                    logServiceInfo(url, user, service);
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

    private static void logServiceInfo(String url, String user, RemoteP11CryptService service)
    {
        StringBuilder sb = new StringBuilder();

        sb.append("Initialized RemoteP11CryptService (url=").append(url);
        sb.append(", user=").append(user).append(")\n");

        PKCS11SlotIdentifier[] slotIds;
        try
        {
            slotIds = service.getSlotIdentifiers();
        } catch (SignerException e)
        {
            LOG.warn("RemoteP11CryptService.getSlotIdentifiers(); SignerException: "
                    + "url={}, user={}, message={}",
                    new Object[]{url, user, e.getMessage()});
            LOG.debug("RemoteP11CryptService.getSlotIdentifiers(); SignerException", e);
            return;
        }

        if(slotIds == null || slotIds.length == 0)
        {
            sb.append("\tNo slot is available");
            LOG.warn("{}", sb);
            return;
        }

        for(PKCS11SlotIdentifier slotId : slotIds)
        {
            String[] keyLabels;
            try
            {
                keyLabels = service.getKeyLabels(slotId);
            } catch (SignerException e)
            {
                LOG.warn("RemoteP11CryptService.getKeyLabels(); SignerException: "
                        + "url={}, user={}, slot={}, message={}",
                        new Object[]{url, user, slotId, e.getMessage()});
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
