// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit;

import org.xipki.util.Args;

import java.io.CharArrayWriter;
import java.net.*;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

/**
 * PCI audit event.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class PciAuditEvent {

  private static final String UNDEFINED = "undefined";

  private static final char DEFAULT_DELIMITER = ' ';

  private static final char DEFAULT_REPLACE_DELIMITER = '_';

  private static final ZoneId ZONE_UTC = ZoneId.of("UTC");

  private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy/MM/dd");

  private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");

  /**
   * 10.3.1 "User Identification"
   */
  private String userId = UNDEFINED;

  /**
   * 10.3.2 "Type of event"
   */
  private String eventType = UNDEFINED;

  /**
   * 10.3.3 "Date and time" (date)
   */
  private final String date;

  /**
   * 10.3.3 "Date and time" (time)
   */
  private final String time;

  /**
   * 10.3.4 "Success or failure indication"
   */
  private String status = UNDEFINED;

  /**
   * 10.3.5 "Origination of Event"
   */
  private String origination;

  /**
   * 10.3.6 "Identity or name of affected data, system component, or resource"
   */
  private String affectedResource = UNDEFINED;

  /**
   * The AuditLevel this Event belongs to.
   */
  private AuditLevel level;

  public PciAuditEvent() {
    this(null);
  }

  public PciAuditEvent(Instant date) {
    if (date == null) {
      date = Instant.now();
    }
    LocalDateTime localDate = LocalDateTime.ofInstant(date, ZONE_UTC);
    this.date = DATE_FORMATTER.format(localDate);
    this.time = TIME_FORMATTER.format(localDate);
    this.level = AuditLevel.INFO;
  } // constructor

  public AuditLevel getLevel() {
    return level;
  }

  public void setLevel(AuditLevel level) {
    this.level = Args.notNull(level, "level");
  }

  public String getUserId() {
    return isBlank(userId) ? UNDEFINED : userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public String getEventType() {
    return isBlank(eventType) ? UNDEFINED : eventType;
  }

  public void setEventType(String eventType) {
    this.eventType = eventType;
  }

  public String getDate() {
    return date;
  }

  public String getTime() {
    return time;
  }

  public String getStatus() {
    return isBlank(status) ? UNDEFINED : status;
  }

  public void setStatus(String status) {
    this.status = status;
  }

  public String getOrigination() {
    if (isBlank(origination)) {
      origination = getHostAddress();
    }

    return origination;
  } // method getOrigination

  public void setOrigination(String origination) {
    this.origination = origination;
  }

  public String getAffectedResource() {
    return isBlank(affectedResource) ? UNDEFINED : affectedResource;
  }

  public void setAffectedResource(String affectedResource) {
    this.affectedResource = affectedResource;
  }

  public String toTextMessage() {
    return toCharArrayWriter("").toString();
  }

  public CharArrayWriter toCharArrayWriter(String prefix) {
    CharArrayWriter buffer = new CharArrayWriter(100);

    final char de = DEFAULT_DELIMITER;

    if (prefix != null && !prefix.isEmpty()) {
      buffer.append(prefix);
    }

    buffer.append(replaceDelimiter(getUserId())).append(de);
    buffer.append(replaceDelimiter(getEventType())).append(de);
    buffer.append(replaceDelimiter(getDate())).append(de);
    buffer.append(replaceDelimiter(getTime())).append(de);
    buffer.append(replaceDelimiter(getStatus())).append(de);
    buffer.append(replaceDelimiter(getOrigination())).append(de);
    buffer.append(replaceDelimiter(getAffectedResource()));

    return buffer;
  } // method toCharArrayWriter

  private static boolean isBlank(CharSequence cs) {
    if (cs == null) {
      return true;
    }

    int strLen = cs.length();
    if (strLen == 0) {
      return true;
    }

    for (int i = 0; i < strLen; i++) {
      if (!Character.isWhitespace(cs.charAt(i))) {
        return false;
      }
    }
    return true;
  } // method isBlank

  private static String replaceDelimiter(String fieldValue) {
    if (fieldValue == null || fieldValue.isEmpty()) {
      return fieldValue;
    }

    return fieldValue.replace(DEFAULT_DELIMITER, DEFAULT_REPLACE_DELIMITER);
  } // method replaceDelimiter

  private static String getHostAddress() {
    List<String> addresses = new LinkedList<>();

    Enumeration<NetworkInterface> interfaces;
    try {
      interfaces = NetworkInterface.getNetworkInterfaces();
    } catch (SocketException ex) {
      return "UNKNOWN";
    }

    while (interfaces.hasMoreElements()) {
      NetworkInterface ni = interfaces.nextElement();
      Enumeration<InetAddress> ee = ni.getInetAddresses();
      while (ee.hasMoreElements()) {
        InetAddress ia = ee.nextElement();
        if (ia instanceof Inet4Address) {
          addresses.add(ia.getHostAddress());
        }
      }
    }

    for (String addr : addresses) {
      if (!addr.startsWith("192.") && !addr.startsWith("127.")) {
        return addr;
      }
    }

    for (String addr : addresses) {
      if (!addr.startsWith("127.")) {
        return addr;
      }
    }

    if (addresses.size() > 0) {
      return addresses.get(0);
    } else {
      try {
        return InetAddress.getLocalHost().getHostAddress();
      } catch (UnknownHostException ex) {
        return "UNKNOWN";
      }
    }
  } // method getHostAddress

}
