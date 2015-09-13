/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.audit.slf4j.impl;

import java.io.CharArrayWriter;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditService;
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.PCIAuditEvent;

/**
 * @author Lijun Liao
 */

public class Slf4jAuditServiceImpl implements AuditService
{
    private static final Logger LOG = LoggerFactory.getLogger(Slf4jAuditServiceImpl.class);

    public Slf4jAuditServiceImpl()
    {
    }

    @Override
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
            LOG.error("{} | LOG - SYSTEM\tstatus: failed\tmessage: {}",
                    AuditLevel.ERROR.getAlignedText(), t.getMessage());
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

    @Override
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
            LOG.error("{} | LOG - SYSTEM\tstatus: failed\tmessage: {}",
                    AuditLevel.ERROR.getAlignedText(), t.getMessage());
        }
    }
}
