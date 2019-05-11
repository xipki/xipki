/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.audit.services;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditEventData;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.AuditServiceRuntimeException;
import org.xipki.audit.AuditStatus;
import org.xipki.audit.PciAuditEvent;
import org.xipki.util.Args;

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
   * The default mode is UDP.
   */
  public static final String DFLT_SYSLOG_PROTOCOL = "udp";

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

  /**
   * The syslog host.
   */
  private String host = DFLT_SYSLOG_HOST;

  /**
   * The default port for the syslog host.
   */
  private int port = DFLT_SYSLOG_PORT;

  /**
   * The protocol for the syslog host.
   */
  private String protocol = DFLT_SYSLOG_PROTOCOL;

  /**
   * The facility for syslog message.
   */
  private String facility = DFLT_SYSLOG_FACILITY;

  /**
   * Message format, rfc_3164 or rfc_5424.
   */
  private String messageFormat = DFLT_MESSAGE_FORMAT;

  private int maxMessageLength = 1024;

  /**
   * If a write to syslog host fails, how many retries should be done, not applied to UDP.
   */
  private int writeRetries;

  /**
   * Set this if the default hostname of the sending side should be avoided.
   */
  private String localname;

  /**
   * The prefix of the syslog message, a space will be added if not empty.
   */
  private String prefix;

  /**
   * Whether uses SSL to secure the communication, not applied to UDP.
   */
  private boolean ssl;

  private boolean initialized;

  public SyslogAuditService() {
  }

  @Override
  public void init(String conf) {
    LOG.info("initializing: {}", SyslogAuditService.class);
    Properties props = loadProperties(conf.trim());
    setFacility(getString(props, "facility", DFLT_SYSLOG_FACILITY));
    setHost(getString(props, "host", DFLT_SYSLOG_HOST));
    setPrefix(getString(props, "prefix", ""));

    String localname = props.getProperty("localname");
    if (localname != null) {
      setLocalname(localname);
    }

    setMaxMessageLength(getInt(props, "maxMessageLength", 1024));
    setPort(getInt(props, "port", DFLT_SYSLOG_PORT));
    setProtocol(getString(props, "protocol", DFLT_SYSLOG_PROTOCOL));
    setWriteRetries(getInt(props, "writeRetries", 2));
    setSsl(getBoolean(props, "ssl", false));
    setMessageFormat(getString(props, "messageFormat", DFLT_MESSAGE_FORMAT));

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

    if ("tcp".equalsIgnoreCase(protocol)) {
      TcpSyslogMessageSender lcSyslog = new TcpSyslogMessageSender();
      syslog = lcSyslog;
      lcSyslog.setSyslogServerHostname(host);
      lcSyslog.setSyslogServerPort(port);
      lcSyslog.setSsl(ssl);
      if (writeRetries > 0) {
        lcSyslog.setMaxRetryCount(writeRetries);
      }
    } else {
      if (!"udp".equalsIgnoreCase(protocol)) {
        LOG.warn("unknown protocol '{}', use the default one 'udp'", this.protocol);
      }

      final UdpSyslogMessageSender lcSyslog = new UdpSyslogMessageSender();
      syslog = lcSyslog;
      lcSyslog.setSyslogServerPort(port);
      lcSyslog.setSyslogServerHostname(host);
    }

    // syslog.setDefaultMessageHostname(host);
    syslog.setMessageFormat(msgFormat);

    Facility sysFacility = notEmpty(facility)
        ? Facility.fromLabel(facility.toUpperCase(Locale.ENGLISH)) : null;

    if (sysFacility == null) {
      LOG.warn("unknown facility, use the default one '{}'", DFLT_SYSLOG_FACILITY);
      sysFacility = Facility.fromLabel(DFLT_SYSLOG_FACILITY.toUpperCase(Locale.ENGLISH));
    }

    if (sysFacility == null) {
      throw new IllegalStateException("should not reach here, sysFacility is null");
    }

    syslog.setDefaultFacility(sysFacility);

    // after we're finished set initialized to true
    this.initialized = true;
    LOG.info("initialized: {}", SyslogAuditService.class);
  } // method init

  @Override
  public void logEvent(AuditEvent event) {
    if (!initialized) {
      LOG.error("syslog audit not initialized");
      return;
    }

    final CharArrayWriter sb = new CharArrayWriter(150);
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

    final List<AuditEventData> eventDataArray = event.getEventDatas();
    for (final AuditEventData m : eventDataArray) {
      if (!(duration >= 0 && "duration".equalsIgnoreCase(m.getName()))) {
        sb.append("\t").append(m.getName()).append(": ").append(m.getValue());
      }
    }

    final int n = sb.size();
    if (n > maxMessageLength) {
      LOG.warn("syslog message exceeds the maximal allowed length: {} > {}, ignore it", n,
          maxMessageLength);
      return;
    }

    final SyslogMessage sm = new SyslogMessage();
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
    } catch (Throwable th) {
      LOG.error("could not send syslog message: {}", th.getMessage());
      LOG.debug("could not send syslog message", th);
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
    } catch (Throwable th) {
      LOG.error("could not send syslog message: {}", th.getMessage());
      LOG.debug("could not send syslog message", th);
    }
  } // method logEvent(PCIAuditEvent)

  public void setFacility(String facility) {
    this.facility = facility;
  }

  public void setHost(String host) {
    this.host = Args.notNull(host, "host");
  }

  public void setPort(int port) {
    this.port = port;
  }

  public void setProtocol(String protocol) {
    this.protocol = Args.notNull(protocol, "protocol");
  }

  public void setLocalname(String localname) {
    this.localname = localname;
  }

  public void setMessageFormat(String messageFormat) {
    this.messageFormat = Args.notNull(messageFormat, "messageFormat");
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

    Severity res;
    switch (auditLevel) {
      case DEBUG:
        res = Severity.DEBUG;
        break;
      case INFO:
        res = Severity.INFORMATIONAL;
        break;
      case WARN:
        res = Severity.WARNING;
        break;
      case ERROR:
        res = Severity.ERROR;
        break;
      default:
        throw new IllegalArgumentException(String.format("unknown auditLevel '%s'", auditLevel));
    }
    return res;
  }

  private static Properties loadProperties(String path) throws AuditServiceRuntimeException {
    if (path == null) {
      return null;
    }

    Path realPath = Paths.get(path);
    if (Files.exists(realPath)) {
      Properties props = new Properties();
      try {
        try (InputStream is = Files.newInputStream(realPath)) {
          props.load(is);
        }
      } catch (IOException ex) {
        throw new AuditServiceRuntimeException("could not load properties from file " + path, ex);
      }
      return props;
    } else {
      throw new AuditServiceRuntimeException("the file " + path + " does not exist");
    }
  }

  private static String getString(Properties props, String key, String dfltValue) {
    if (props == null) {
      return dfltValue;
    } else {
      String value = props.getProperty(key);
      return value == null ? dfltValue : value;
    }
  }

  private static int getInt(Properties props, String key, int dfltValue) {
    if (props == null) {
      return dfltValue;
    } else {
      String value = props.getProperty(key);
      return value == null ? dfltValue : Integer.parseInt(value);
    }
  }

  private static boolean getBoolean(Properties props, String key, boolean dfltValue) {
    if (props == null) {
      return dfltValue;
    } else {
      String value = props.getProperty(key);
      return value == null ? dfltValue : Boolean.parseBoolean(value);
    }
  }

}
