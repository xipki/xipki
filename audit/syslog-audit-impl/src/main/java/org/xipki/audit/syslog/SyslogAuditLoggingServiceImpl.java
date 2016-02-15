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

package org.xipki.audit.syslog;

import java.io.CharArrayWriter;
import java.io.IOException;
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

import com.cloudbees.syslog.Facility;
import com.cloudbees.syslog.MessageFormat;
import com.cloudbees.syslog.Severity;
import com.cloudbees.syslog.SyslogMessage;
import com.cloudbees.syslog.sender.AbstractSyslogMessageSender;
import com.cloudbees.syslog.sender.TcpSyslogMessageSender;
import com.cloudbees.syslog.sender.UdpSyslogMessageSender;

/**
 * @author Lijun Liao
 */

public class SyslogAuditLoggingServiceImpl implements AuditLoggingService
{
    private static final Logger LOG = LoggerFactory.getLogger(SyslogAuditLoggingServiceImpl.class);

    private static final DateFormat df = new SimpleDateFormat("yyyy.MM.dd '-' HH:mm:ss.SSS z");

    /**
     * The default port is 514.
     */
    public static final int DFLT_SYSLOG_PORT = 514;

    /**
     * The default mode is TCP.
     */
    public static final String DFLT_SYSLOG_PROTOCOL = "tcp";

    /**
     * The default facility is USER.
     */
    public static final String DFLT_SYSLOG_FACILITY = "user";

    /**
     * The default ip is localhost.
     */
    public static final String DFLT_SYSLOG_HOST = "localhost";

    /**
     * The default message format is rfc_5424.
     */
    public static final String DFLT_MESSAGE_FORMAT = "rfc_5424";

    /**
     * The syslog client instance.
     */
    protected AbstractSyslogMessageSender syslog;

    private String host = DFLT_SYSLOG_HOST;

    private int port = DFLT_SYSLOG_PORT;

    private String protocol = DFLT_SYSLOG_PROTOCOL;

    private String facility = DFLT_SYSLOG_FACILITY;

    private String messageFormat = DFLT_MESSAGE_FORMAT;

    private int maxMessageLength = 1024;

    private int writeRetries;

    private String localname;

    private String prefix;

    private boolean ssl;

    private boolean initialized;

    public SyslogAuditLoggingServiceImpl()
    {
    }

    @Override
    public void logEvent(final AuditEvent event)
    {
        if(event == null)
        {
            return;
        }

        if (!initialized)
        {
            LOG.error("Syslog audit not initialiazed");
            return;
        }

        CharArrayWriter sb = new CharArrayWriter(150);
        if (notEmpty(prefix))
        {
            sb.append(prefix);
        }

        AuditStatus status = event.getStatus();
        if(status == null)
        {
            status = AuditStatus.UNDEFINED;
        }
        sb.append("\tstatus: ").append(status.name());

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
                    sb.append(element.getNumberValue().toString());
                    break;
                case TEXT:
                    sb.append(element.getTextValue());
                    break;
                case TIMESTAMP:
                    sb.append(df.format(element.getTimestampValue()));
                    break;
                }
            }
        }

        final int n = sb.size();
        if (n > maxMessageLength)
        {
            LOG.warn("syslog message exceeds the maximal allowed length: {} > {}, ignore it",
                    n, maxMessageLength);
            return;
        }

        SyslogMessage sm = new SyslogMessage();
        sm.setFacility(syslog.getDefaultFacility());
        if (notEmpty(localname))
        {
            sm.setHostname(localname);
        }
        sm.setAppName(event.getApplicationName());
        sm.setSeverity(getSeverity(event.getLevel()));

        Date timestamp = event.getTimestamp();
        if (timestamp != null)
        {
            sm.setTimestamp(timestamp);
        }

        sm.setMsgId(event.getName());
        sm.setMsg(sb);

        try
        {
            syslog.sendMessage(sm);
        } catch (IOException ex)
        {
            LOG.error("Could not send syslog message: {}", ex.getMessage());
            LOG.debug("Could not send syslog message", ex);
        }

        try
        {
            syslog.sendMessage(sb);
        } catch (IOException ex)
        {
            LOG.error("Could not send syslog message: {}", ex.getMessage());
            LOG.debug("Could not send syslog message", ex);
        }
    }

    public void logEvent(final PCIAuditEvent event)
    {
        if(event == null)
        {
            return;
        }

        if (!initialized)
        {
            LOG.error("Syslog audit not initialiazed");
            return;
        }

        CharArrayWriter msg = event.toCharArrayWriter(prefix);
        final int n = msg.size();
        if (n > maxMessageLength)
        {
            LOG.warn("syslog message exceeds the maximal allowed length: {} > {}, ignore it",
                    n, maxMessageLength);
            return;
        }

        SyslogMessage sm = new SyslogMessage();
        sm.setFacility(syslog.getDefaultFacility());
        if (notEmpty(localname))
        {
            sm.setHostname(localname);
        }

        sm.setSeverity(getSeverity(event.getLevel()));
        sm.setMsg(msg);

        try
        {
            syslog.sendMessage(sm);
        } catch (IOException ex)
        {
            LOG.error("Could not send syslog message: {}", ex.getMessage());
            LOG.debug("Could not send syslog message", ex);
        }
    }

    public void init()
    {
        if (initialized)
        {
            return;
        }

        LOG.info("initializing: {}", SyslogAuditLoggingServiceImpl.class);

        MessageFormat msgFormat;
        if ("rfc3164".equalsIgnoreCase(messageFormat)
                || "rfc_3164".equalsIgnoreCase(messageFormat))
                {
            msgFormat = MessageFormat.RFC_3164;
        } else if ("rfc5424".equalsIgnoreCase(messageFormat)
                || "rfc_5424".equalsIgnoreCase(messageFormat))
                {
            msgFormat = MessageFormat.RFC_5424;
        } else
        {
            LOG.warn("invalid message format '{}', use the default one '{}'",
                    messageFormat, DFLT_MESSAGE_FORMAT);
            msgFormat = MessageFormat.RFC_5424;
        }

        if ("udp".equalsIgnoreCase(protocol))
        {
            syslog = new UdpSyslogMessageSender();
            ((UdpSyslogMessageSender) syslog).setSyslogServerPort(port);
        } else if ("tcp".equalsIgnoreCase(protocol))
        {
            syslog = new TcpSyslogMessageSender();
            ((TcpSyslogMessageSender) syslog).setSyslogServerPort(port);
            ((TcpSyslogMessageSender) syslog).setSsl(ssl);

            if (writeRetries > 0)
            {
                ((TcpSyslogMessageSender) syslog).setMaxRetryCount(writeRetries);
            }
        } else
        {
            LOG.warn("unknown protocol '{}', use the default one 'udp'", this.protocol);
            syslog = new UdpSyslogMessageSender();
            ((UdpSyslogMessageSender) syslog).setSyslogServerPort(port);
        }

        syslog.setDefaultMessageHostname(host);
        syslog.setMessageFormat(msgFormat);

        Facility sysFacility = null;
        if (notEmpty(facility))
        {
            sysFacility = Facility.fromLabel(facility.toUpperCase());
        }

        if (sysFacility == null)
        {
            LOG.warn("unknown facility, use the default one '{}'", DFLT_SYSLOG_FACILITY);
            sysFacility = Facility.fromLabel(DFLT_SYSLOG_FACILITY.toUpperCase());
        }

        if (sysFacility == null)
        {
            throw new RuntimeException("should not reach here, sysFacility is null");
        }

        syslog.setDefaultFacility(sysFacility);

        // after we're finished set initialized to true
        this.initialized = true;
        LOG.info("Initialized: {}", SyslogAuditLoggingServiceImpl.class);
    } // method init

    public void destroy()
    {
        LOG.info("destroying: {}", SyslogAuditLoggingServiceImpl.class);
        LOG.info("destroyed: {}", SyslogAuditLoggingServiceImpl.class);
    }

    public void setFacility(
            final String facility)
            {
        this.facility = facility;
    }

    public void setHost(
            final String host)
            {
        this.host = host;
    }

    public void setPort(
            final int port)
            {
        this.port = port;
    }

    public void setProtocol(
            final String protocol)
            {
        this.protocol = protocol;
    }

    public void setLocalname(
            final String localname)
            {
        this.localname = localname;
    }

    public void setMessageFormat(
            final String messageFormat)
            {
        this.messageFormat = messageFormat;
    }

    public void setWriteRetries(
            final int writeRetries)
            {
        this.writeRetries = writeRetries;
    }

    public void setPrefix(
            final String prefix)
            {
        if (notEmpty(prefix))
        {
            if (prefix.charAt(prefix.length() - 1) != ' ')
            {
                this.prefix = prefix + " ";
            }
        } else
        {
            this.prefix = null;
        }
    }

    public void setMaxMessageLength(
            final int maxMessageLength)
            {
        if (maxMessageLength <= 0)
        {
            this.maxMessageLength = 1023;
        } else
        {
            this.maxMessageLength = maxMessageLength;
        }
    }

    public void setSsl(
            final boolean ssl)
            {
        this.ssl = ssl;
    }

    private static boolean notEmpty(
            final String text)
            {
        return text != null && !text.isEmpty();
    }

    private static Severity getSeverity(
            final AuditLevel auditLevel)
            {
        if (auditLevel == null)
        {
            return Severity.INFORMATIONAL;
        }

        switch (auditLevel)
        {
        case DEBUG:
            return Severity.DEBUG;
        case INFO:
            return Severity.INFORMATIONAL;
        case WARN:
            return Severity.WARNING;
        case ERROR:
            return Severity.ERROR;
        default:
            throw new RuntimeException(
                String.format("unknown auditLevel '%s'", auditLevel));
        }
    }

    private static final char[] HEX_CHAR_TABLE = "0123456789ABCDEF".toCharArray();
    private static String toHexString(byte[] raw)
    {
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
