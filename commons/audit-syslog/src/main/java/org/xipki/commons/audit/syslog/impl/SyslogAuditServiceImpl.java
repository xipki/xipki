/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.commons.audit.syslog.impl;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.audit.api.AuditEvent;
import org.xipki.commons.audit.api.AuditEventData;
import org.xipki.commons.audit.api.AuditLevel;
import org.xipki.commons.audit.api.AuditService;
import org.xipki.commons.audit.api.AuditStatus;
import org.xipki.commons.audit.api.PciAuditEvent;

import com.cloudbees.syslog.Facility;
import com.cloudbees.syslog.MessageFormat;
import com.cloudbees.syslog.Severity;
import com.cloudbees.syslog.SyslogMessage;
import com.cloudbees.syslog.sender.AbstractSyslogMessageSender;
import com.cloudbees.syslog.sender.TcpSyslogMessageSender;
import com.cloudbees.syslog.sender.UdpSyslogMessageSender;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SyslogAuditServiceImpl implements AuditService {

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
  public static final String  DFLT_SYSLOG_FACILITY = "user";

  /**
   * The default ip is localhost.
   */
  public static final String DFLT_SYSLOG_HOST = "localhost";

  /**
   * The default message format is rfc_5424.
   */
  public static final String DFLT_MESSAGE_FORMAT = "rfc_5424";

  private static final Logger LOG = LoggerFactory.getLogger(SyslogAuditServiceImpl.class);

  /**
   * The syslog4j client instance.
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

  public SyslogAuditServiceImpl() {
  }

  @Override
  public void logEvent(
      final AuditEvent event) {
    if (event == null) {
      return;
    }

    if (!initialized) {
      LOG.error("Syslog audit not initialiazed");
      return;
    }

    CharArrayWriter sb = new CharArrayWriter(150);
    if (notEmpty(prefix)) {
      sb.append(prefix);
    }

    AuditStatus status = event.getStatus();
    if (status == null) {
      status = AuditStatus.UNDEFINED;
    }

    sb.append("\tstatus: ").append(status.name());

    long duration = event.getDuration();
    if (duration >= 0) {
      sb.append("\tduration: ").append(Long.toString(duration));
    }

    List<AuditEventData> eventDataArray = event.getEventDatas();
    for (AuditEventData m : eventDataArray) {
      if (duration >= 0 && "duration".equalsIgnoreCase(m.getName())) {
        continue;
      }
      sb.append("\t").append(m.getName()).append(": ").append(m.getValue());
    }

    final int n = sb.size();
    if (n > maxMessageLength) {
      LOG.warn("syslog message exceeds the maximal allowed length: {} > {}, ignore it",
          n, maxMessageLength);
      return;
    }

    SyslogMessage sm = new SyslogMessage();
    sm.setFacility(syslog.getDefaultFacility());
    if (notEmpty(localname)) {
      sm.setHostname(localname);
    }
    sm.setAppName(event.getApplicationName());
    sm.setSeverity(getSeverity(event.getLevel()));

    Date timestamp = event.getTimestamp();
    if (timestamp != null) {
      sm.setTimestamp(timestamp);
    }

    sm.setMsgId(event.getName());
    sm.setMsg(sb);

    try {
      syslog.sendMessage(sm);
    } catch (IOException ex) {
      LOG.error("Could not send syslog message: {}", ex.getMessage());
      LOG.debug("Could not send syslog message", ex);
    }
  } // method logEvent(AuditEvent)

  @Override
  public void logEvent(
      final PciAuditEvent event) {
    if (event == null) {
      return;
    }

    if (!initialized) {
      LOG.error("Syslog audit not initialiazed");
      return;
    }

    CharArrayWriter msg = event.toCharArrayWriter(prefix);
    final int n = msg.size();
    if (n > maxMessageLength) {
      LOG.warn("syslog message exceeds the maximal allowed length: {} > {}, ignore it",
          n, maxMessageLength);
      return;
    }

    SyslogMessage sm = new SyslogMessage();
    sm.setFacility(syslog.getDefaultFacility());
    if (notEmpty(localname)) {
      sm.setHostname(localname);
    }

    sm.setSeverity(getSeverity(event.getLevel()));
    sm.setMsg(msg);

    try {
      syslog.sendMessage(sm);
    } catch (IOException ex) {
      LOG.error("Could not send syslog message: {}", ex.getMessage());
      LOG.debug("Could not send syslog message", ex);
    }
  } // method logEvent(PCIAuditEvent)

  public void init() {
    if (initialized) {
      return;
    }

    LOG.info("initializing: {}", SyslogAuditServiceImpl.class);

    MessageFormat msgFormat;
    if ("rfc3164".equalsIgnoreCase(messageFormat)
        || "rfc_3164".equalsIgnoreCase(messageFormat)) {
      msgFormat = MessageFormat.RFC_3164;
    } else if ("rfc5424".equalsIgnoreCase(messageFormat)
        || "rfc_5424".equalsIgnoreCase(messageFormat)) {
      msgFormat = MessageFormat.RFC_5424;
    } else {
      LOG.warn("invalid message format '{}', use the default one '{}'",
          messageFormat, DFLT_MESSAGE_FORMAT);
      msgFormat = MessageFormat.RFC_5424;
    }

    if ("udp".equalsIgnoreCase(protocol)) {
      syslog = new UdpSyslogMessageSender();
      ((UdpSyslogMessageSender) syslog).setSyslogServerPort(port);
    } else if ("tcp".equalsIgnoreCase(protocol)) {
      syslog = new TcpSyslogMessageSender();
      ((TcpSyslogMessageSender) syslog).setSyslogServerPort(port);
      ((TcpSyslogMessageSender) syslog).setSsl(ssl);

      if (writeRetries > 0) {
        ((TcpSyslogMessageSender) syslog).setMaxRetryCount(writeRetries);
      }
    } else {
      LOG.warn("unknown protocol '{}', use the default one 'udp'", this.protocol);
      syslog = new UdpSyslogMessageSender();
      ((UdpSyslogMessageSender) syslog).setSyslogServerPort(port);
    }

    syslog.setDefaultMessageHostname(host);
    syslog.setMessageFormat(msgFormat);

    Facility sysFacility = null;
    if (notEmpty(facility)) {
      sysFacility = Facility.fromLabel(facility.toUpperCase());
    }

    if (sysFacility == null) {
      LOG.warn("unknown facility, use the default one '{}'", DFLT_SYSLOG_FACILITY);
      sysFacility = Facility.fromLabel(DFLT_SYSLOG_FACILITY.toUpperCase());
    }

    if (sysFacility == null) {
      throw new RuntimeException("should not reach here, sysFacility is null");
    }

    syslog.setDefaultFacility(sysFacility);

    // after we're finished set initialized to true
    this.initialized = true;
    LOG.info("Initialized: {}", SyslogAuditServiceImpl.class);
  } // method init

  public void destroy() {
    LOG.info("destroying: {}", SyslogAuditServiceImpl.class);
    LOG.info("destroyed: {}", SyslogAuditServiceImpl.class);
  }

  public void setFacility(
      final String facility) {
    this.facility = facility;
  }

  public void setHost(
      final String host) {
    this.host = host;
  }

  public void setPort(
      final int port) {
    this.port = port;
  }

  public void setProtocol(
      final String protocol) {
    this.protocol = protocol;
  }

  public void setLocalname(
      final String localname) {
    this.localname = localname;
  }

  public void setMessageFormat(
      final String messageFormat) {
    this.messageFormat = messageFormat;
  }

  public void setWriteRetries(
      final int writeRetries) {
    this.writeRetries = writeRetries;
  }

  public void setPrefix(
      final String prefix) {
    if (notEmpty(prefix)) {
      if (prefix.charAt(prefix.length() - 1) != ' ') {
        this.prefix = prefix + " ";
      }
    } else {
      this.prefix = null;
    }
  }

  public void setMaxMessageLength(
      final int maxMessageLength) {
    if (maxMessageLength <= 0) {
      this.maxMessageLength = 1023;
    } else {
      this.maxMessageLength = maxMessageLength;
    }
  }

  public void setSsl(
      final boolean ssl) {
    this.ssl = ssl;
  }

  private static boolean notEmpty(
      final String text) {
    return text != null && !text.isEmpty();
  }

  private static Severity getSeverity(
      final AuditLevel auditLevel) {
    if (auditLevel == null) {
      return Severity.INFORMATIONAL;
    }

    switch (auditLevel) {
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

}
