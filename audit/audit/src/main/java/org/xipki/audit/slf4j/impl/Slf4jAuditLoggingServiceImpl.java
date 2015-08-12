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

package org.xipki.audit.slf4j.impl;

import java.io.CharArrayWriter;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.PCIAuditEvent;

/**
 * @author Lijun Liao
 */

public class Slf4jAuditLoggingServiceImpl implements AuditLoggingService
{
    private static final Logger LOG = LoggerFactory.getLogger(Slf4jAuditLoggingServiceImpl.class);

    public Slf4jAuditLoggingServiceImpl()
    {
    }

    public void logEvent(
            final AuditEvent event)
    {
        if(event == null)
        {
            return;
        }

        try
        {
            switch(event.getLevel())
            {
            case DEBUG:
                if(LOG.isDebugEnabled())
                {
                    LOG.debug("{}", createMessage(event));
                }
                break;
            default:
                LOG.info("{}", createMessage(event));
                break;
            } // end switch
        }catch(Throwable t)
        {
            LOG.error("{} | LOG - SYSTEM\tstatus: failed\tmessage: {}", AuditLevel.ERROR.getAlignedText(), t.getMessage());
        }
    }

    private static String createMessage(
            final AuditEvent event)
    {
        StringBuilder sb = new StringBuilder();

        sb.append(event.getLevel().getAlignedText()).append(" | ");

        String applicationName = event.getApplicationName();
        if(applicationName == null)
        {
            applicationName = "undefined";
        }

        String name = event.getName();
        if(name == null)
        {
            name = "undefined";
        }

        sb.append(applicationName).append(" - ").append(name);

        AuditStatus status = event.getStatus();
        if(status == null)
        {
            status = AuditStatus.UNDEFINED;
        }
        sb.append(":\tstatus: ").append(status.name());
        List<AuditEventData> eventDataArray = event.getEventDatas();

        long duration = event.getDuration();
        if(duration >= 0)
        {
            sb.append("\tduration: ").append(duration);
        }

        if ((eventDataArray != null) && (eventDataArray.size() > 0))
        {
            for (AuditEventData m : eventDataArray)
            {
                if(duration >= 0 && "duration".equalsIgnoreCase(m.getName()))
                {
                    continue;
                }

                sb.append("\t").append(m.getName()).append(": ").append(m.getValue());
            }
        }

        return sb.toString();
    }

    public void logEvent(
            final PCIAuditEvent event)
    {
        if(event == null)
        {
            return;
        }

        try
        {
            CharArrayWriter msg = event.toCharArrayWriter("");
            AuditLevel al = event.getLevel();
            switch(al)
            {
            case DEBUG:
                if(LOG.isDebugEnabled())
                {
                    LOG.debug("{} | {}", al.getAlignedText(), msg);
                }
                break;
            default:
                LOG.info("{} | {}", al.getAlignedText(), msg);
                break;
            } // end switch
        }catch(Throwable t)
        {
            LOG.error("{} | LOG - SYSTEM\tstatus: failed\tmessage: {}", AuditLevel.ERROR.getAlignedText(), t.getMessage());
        }
    }
}
