/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.audit.api;

import java.util.concurrent.ConcurrentLinkedDeque;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Lijun Liao
 */

public class AuditLoggingServiceRegisterImpl implements AuditLoggingServiceRegister
{
    private static final Logger LOG = LoggerFactory.getLogger(AuditLoggingServiceRegisterImpl.class);
    private ConcurrentLinkedDeque<AuditLoggingService> services = new ConcurrentLinkedDeque<>();

    public AuditLoggingService getAuditLoggingService()
    {
        return services.isEmpty() ? null : services.getLast();
    }

    public void bindService(AuditLoggingService service)
    {
        //might be null if dependency is optional
        if (service == null)
        {
            LOG.debug("bindModule invoked with null.");
            return;
        }

        boolean replaced = services.remove(service);
        services.add(service);
        LOG.debug("{} AuditLoggingService binding for {}", (replaced ? "replaced" : "added"), service);
    }

    public void unbindService(AuditLoggingService service)
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
            LOG.debug("Caught Exception({}). service is probably destroyed.", e.getMessage());
        }
    }
}
