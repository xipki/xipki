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

package org.xipki.audit.slf4j;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditEventDataType;
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

    private static final DateFormat df = new SimpleDateFormat("yyyy.MM.dd '-' HH:mm:ss.SSS z");

    public Slf4jAuditLoggingServiceImpl()
    {
    }

    @Override
    public void logEvent(AuditEvent event)
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
            }
        }catch(Throwable t)
        {
            LOG.error("{} | LOG - SYSTEM\tstatus: failed\tmessage: {}", AuditLevel.ERROR.getAlignedText(), t.getMessage());
        }
    }

    private static String createMessage(AuditEvent event)
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

        if ((eventDataArray != null) && (eventDataArray.size() > 0))
        {
            for (AuditEventData element : eventDataArray)
            {
                sb.append("\t");
                sb.append(element.getName());
                sb.append(": ");

                AuditEventDataType eventDataType = element.getEventDataType();
                switch(eventDataType)
                {
                case BINARY:
                    sb.append(toHexString(element.getBinaryValue()));
                    break;
                case NUMBER:
                    sb.append(element.getNumberValue());
                    break;
                case TEXT:
                    sb.append(element.getTextValue());
                    break;
                case TIMESTAMP:
                    Date t = element.getTimestampValue();
                    String value;
                    if(t == null)
                    {
                        value = "undefined";
                    } else
                    {
                        synchronized (df)
                        {
                            value = df.format(element.getTimestampValue());
                        }
                    }
                    sb.append(value);
                    break;
                }
            }
        }

        return sb.toString();
    }

    public void logEvent(PCIAuditEvent event)
    {
        if(event == null)
        {
            return;
        }

        try
        {
            AuditLevel al = event.getLevel();
            switch(al)
            {
                case DEBUG:
                    if(LOG.isDebugEnabled())
                    {
                        LOG.debug("{} | {}", al.getAlignedText(), event.createMessage());
                    }
                    break;
                default:
                    LOG.info("{} | {}", al.getAlignedText(), event.createMessage());
                    break;
            }

            event.createMessage();
        }catch(Throwable t)
        {
            LOG.error("{} | LOG - SYSTEM\tstatus: failed\tmessage: {}", AuditLevel.ERROR.getAlignedText(), t.getMessage());
        }
    }

    private static final char[] HEX_CHAR_TABLE = "0123456789ABCDEF".toCharArray();
    private static String toHexString(byte[] raw)
    {
        if(raw == null)
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (byte b : raw)
        {
            int v = (b < 0) ? 256 + b : b;
            sb.append(HEX_CHAR_TABLE[v >>> 4]);
            sb.append(HEX_CHAR_TABLE[v & 0x0F]);
            sb.append(" ");
        }
        return sb.toString();
    }
}
