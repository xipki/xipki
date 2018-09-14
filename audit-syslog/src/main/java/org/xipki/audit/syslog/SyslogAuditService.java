/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.audit.syslog;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditEventData;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditStatus;
import org.xipki.audit.PciAuditEvent;

import com.cloudbees.syslog.Facility;
import com.cloudbees.syslog.MessageFormat;
import com.cloudbees.syslog.Severity;
import com.cloudbees.syslog.SyslogMessage;
import com.cloudbees.syslog.sender.AbstractSyslogMessageSender;
import com.cloudbees.syslog.sender.TcpSyslogMessageSender;
import com.cloudbees.syslog.sender.UdpSyslogMessageSender;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SyslogAuditService implements AuditService {

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
   * The default IP is localhost.
   */
  public static final String DFLT_SYSLOG_HOST = "localhost";

  /**
   * The default message format is rfc_5424.
   */
  public static final String DFLT_MESSAGE_FORMAT = "rfc_5424";

  private static final Logger LOG = LoggerFactory.getLogger(SyslogAuditService.class);

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

  public SyslogAuditService() {
  }

  @Override
  public void logEvent(AuditEvent event) {
    if (!initialized) {
      LOG.error("syslog audit not initialized");
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
      LOG.warn("syslog message exceeds the maximal allowed length: {} > {}, ignore it", n,
          maxMessageLength);
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
      LOG.error("could not send syslog message: {}", ex.getMessage());
      LOG.debug("could not send syslog message", ex);
    }
  } // method logEvent(AuditEvent)

  @Override
  public void logEvent(PciAuditEvent event) {
    if (!initialized) {
      LOG.error("syslog audit not initialiazed");
      return;
    }

    CharArrayWriter msg = event.toCharArrayWriter(prefix);
    final int n = msg.size();
    if (n > maxMessageLength) {
      LOG.warn("syslog message exceeds the maximal allowed length: {} > {}, ignore it", n,
          maxMessageLength);
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
      LOG.error("could not send syslog message: {}", ex.getMessage());
      LOG.debug("could not send syslog message", ex);
    }
  } // method logEvent(PCIAuditEvent)

  public void init() {
    if (initialized) {
      return;
    }

    LOG.info("initializing: {}", SyslogAuditService.class);

    MessageFormat msgFormat;
    if ("rfc3164".equalsIgnoreCase(messageFormat) || "rfc_3164".equalsIgnoreCase(messageFormat)) {
      msgFormat = MessageFormat.RFC_3164;
    } else if ("rfc5424".equalsIgnoreCase(messageFormat)
        || "rfc_5424".equalsIgnoreCase(messageFormat)) {
      msgFormat = MessageFormat.RFC_5424;
    } else {
      LOG.warn("invalid message format '{}', use the default one '{}'", messageFormat,
          DFLT_MESSAGE_FORMAT);
      msgFormat = MessageFormat.RFC_5424;
    }

    if ("udp".equalsIgnoreCase(protocol)) {
      UdpSyslogMessageSender lcSyslog = new UdpSyslogMessageSender();
      syslog = lcSyslog;
      lcSyslog.setSyslogServerPort(port);
    } else if ("tcp".equalsIgnoreCase(protocol)) {
      TcpSyslogMessageSender lcSyslog = new TcpSyslogMessageSender();
      syslog = lcSyslog;
      lcSyslog.setSyslogServerPort(port);
      lcSyslog.setSsl(ssl);
      if (writeRetries > 0) {
        lcSyslog.setMaxRetryCount(writeRetries);
      }
    } else {
      LOG.warn("unknown protocol '{}', use the default one 'udp'", this.protocol);
      UdpSyslogMessageSender lcSyslog = new UdpSyslogMessageSender();
      syslog = lcSyslog;
      lcSyslog.setSyslogServerPort(port);
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
    LOG.info("initialized: {}", SyslogAuditService.class);
  } // method init

  public void destroy() {
    LOG.info("destroying: {}", SyslogAuditService.class);
    LOG.info("destroyed: {}", SyslogAuditService.class);
  }

  public void setFacility(String facility) {
    this.facility = facility;
  }

  public void setHost(String host) {
    this.host = Objects.requireNonNull(host, "host must not be null");
  }

  public void setPort(int port) {
    this.port = port;
  }

  public void setProtocol(String protocol) {
    this.protocol = Objects.requireNonNull(protocol, "protocol must not be null");
  }

  public void setLocalname(String localname) {
    this.localname = localname;
  }

  public void setMessageFormat(String messageFormat) {
    this.messageFormat = Objects.requireNonNull(messageFormat, "messageFormat must not be null");
  }

  public void setWriteRetries(int writeRetries) {
    this.writeRetries = writeRetries;
  }

  public void setPrefix(String prefix) {
    if (notEmpty(prefix)) {
      if (prefix.charAt(prefix.length() - 1) != ' ') {
        this.prefix = prefix + " ";
      }
    } else {
      this.prefix = null;
    }
  }

  public void setMaxMessageLength(int maxMessageLength) {
    this.maxMessageLength = (maxMessageLength <= 0) ? 1023 : maxMessageLength;
  }

  public void setSsl(boolean ssl) {
    this.ssl = ssl;
  }

  private static boolean notEmpty(String text) {
    return text != null && !text.isEmpty();
  }

  private static Severity getSeverity(AuditLevel auditLevel) {
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
        throw new RuntimeException(String.format("unknown auditLevel '%s'", auditLevel));
    }
  }

}
