/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.audit.api;

import java.util.concurrent.ConcurrentLinkedDeque;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.slf4j.Slf4jAuditLoggingServiceImpl;

/**
 * @author Lijun Liao
 */

public class AuditLoggingServiceRegisterImpl implements AuditLoggingServiceRegister
{
    private static final Logger LOG = LoggerFactory.getLogger(AuditLoggingServiceRegisterImpl.class);
    private ConcurrentLinkedDeque<AuditLoggingService> services = new ConcurrentLinkedDeque<>();
    private Slf4jAuditLoggingServiceImpl defaultAuditLoggingService = new Slf4jAuditLoggingServiceImpl();

    public AuditLoggingService getAuditLoggingService()
    {
        return services.isEmpty() ? defaultAuditLoggingService : services.getLast();
    }

    public void bindService(AuditLoggingService service)
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
