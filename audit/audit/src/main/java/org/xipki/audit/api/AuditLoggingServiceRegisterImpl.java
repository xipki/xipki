/*
 * Copyright (c) 2015 Lijun Liao
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

package org.xipki.audit.api;

import java.util.concurrent.ConcurrentLinkedDeque;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.slf4j.impl.Slf4jAuditLoggingServiceImpl;

/**
 * @author Lijun Liao
 */

public class AuditLoggingServiceRegisterImpl implements AuditLoggingServiceRegister
{
    private static final Logger LOG = LoggerFactory.getLogger(AuditLoggingServiceRegisterImpl.class);
    private ConcurrentLinkedDeque<AuditLoggingService> services = new ConcurrentLinkedDeque<AuditLoggingService>();
    private Slf4jAuditLoggingServiceImpl defaultAuditLoggingService = new Slf4jAuditLoggingServiceImpl();

    private boolean auditEnabled;

    public AuditLoggingService getAuditLoggingService()
    {
        if(auditEnabled)
        {
            return services.isEmpty() ? defaultAuditLoggingService : services.getLast();
        }
        else
        {
            return null;
        }
    }

    public void bindService(
            final AuditLoggingService service)
    {
        //might be null if dependency is optional
        if (service == null)
        {
            LOG.debug("bindService invoked with null.");
            return;
        }

        boolean replaced = services.remove(service);
        services.add(service);
        LOG.debug("{} AuditLoggingService binding for {}", (replaced ? "replaced" : "added"), service);
    }

    public void unbindService(
            final AuditLoggingService service)
    {
        //might be null if dependency is optional
        if (service == null)
        {
            LOG.debug("unbindService invoked with null.");
            return;
        }

        try
        {
            if(services.remove(service))
            {
                LOG.debug("removed AuditLoggingService binding for {}", service);
            }
            else
            {
                LOG.debug("no AuditLoggingService binding found to remove for '{}'", service);
            }
        } catch (Exception e)
        {
            LOG.debug("caught Exception({}). service is probably destroyed.", e.getMessage());
        }
    }

    public void setAuditEnabled(
            final boolean auditEnabled)
    {
        this.auditEnabled = auditEnabled;
    }

    public boolean isAuditEnabled()
    {
        return auditEnabled;
    }
}
