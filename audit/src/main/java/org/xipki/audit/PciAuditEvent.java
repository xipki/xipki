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

package org.xipki.audit;

import java.io.CharArrayWriter;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PciAuditEvent {

    private static final String UNDEFINED = "undefined";

    private static final char DEFAULT_DELIMITER = ' ';

    private static final String DEFAULT_REPLACE_DELIMITER = "_";

    private static final ZoneId ZONE_UTC = ZoneId.of("UTC");

    private static final DateTimeFormatter DATE_FORMATTER
            = DateTimeFormatter.ofPattern("yyyy/MM/dd");

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

    public PciAuditEvent(final Date date) {
        Objects.requireNonNull(date, "date must not be null");
        LocalDateTime localDate = LocalDateTime.ofInstant(date.toInstant(), ZONE_UTC);
        this.date = DATE_FORMATTER.format(localDate);
        this.time = TIME_FORMATTER.format(localDate);
        this.level = AuditLevel.INFO;
    }

    public AuditLevel level() {
        return level;
    }

    public void setLevel(final AuditLevel level) {
        this.level = Objects.requireNonNull(level, "level must not be null");
    }

    public String userId() {
        if (isBlank(this.userId)) {
            return UNDEFINED;
        }

        return this.userId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String eventType() {
        if (isBlank(this.eventType)) {
            return UNDEFINED;
        }

        return this.eventType;
    }

    public void setEventType(final String eventType) {
        this.eventType = eventType;
    }

    public String date() {
        return date;
    }

    public String time() {
        return time;
    }

    public String status() {
        if (isBlank(this.status)) {
            return UNDEFINED;
        }

        return this.status;
    }

    public void setStatus(final String status) {
        this.status = status;
    }

    public String origination() {
        if (isBlank(origination)) {
            origination = getHostAddress();
        }

        return origination;
    }

    public void setOrigination(final String origination) {
        this.origination = origination;
    }

    public String affectedResource() {
        if (isBlank(this.affectedResource)) {
            return UNDEFINED;
        }

        return this.affectedResource;
    }

    public void setAffectedResource(final String affectedResource) {
        this.affectedResource = affectedResource;
    }

    public CharArrayWriter toCharArrayWriter(final String prefix) {
        CharArrayWriter buffer = new CharArrayWriter(100);

        final char delimiter = DEFAULT_DELIMITER;
        final String replaceDelimiter = DEFAULT_REPLACE_DELIMITER;

        if (prefix != null && !prefix.isEmpty()) {
            buffer.append(prefix);
        }

        buffer.append(replaceDelimiter(userId(), delimiter, replaceDelimiter)).append(delimiter);
        buffer.append(replaceDelimiter(eventType(), delimiter, replaceDelimiter))
                .append(delimiter);
        buffer.append(replaceDelimiter(date(), delimiter, replaceDelimiter)).append(delimiter);
        buffer.append(replaceDelimiter(time(), delimiter, replaceDelimiter)).append(delimiter);
        buffer.append(replaceDelimiter(status(), delimiter, replaceDelimiter)).append(delimiter);
        buffer.append(replaceDelimiter(origination(), delimiter, replaceDelimiter))
                .append(delimiter);
        buffer.append(replaceDelimiter(affectedResource(), delimiter, replaceDelimiter));

        return buffer;
    }

    private static boolean isBlank(final CharSequence cs) {
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
    }

    private static String replaceDelimiter(final String fieldValue, final char delimiter,
            final String replaceDelimiter) {
        if (replaceDelimiter == null || replaceDelimiter.length() < 1
                || fieldValue == null || fieldValue.length() < 1) {
            return fieldValue;
        }

        return fieldValue.replaceAll("\\" + delimiter, replaceDelimiter);
    }

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
    }

}
