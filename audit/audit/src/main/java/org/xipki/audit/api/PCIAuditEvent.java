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

package org.xipki.audit.api;

import java.io.CharArrayWriter;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Lijun Liao
 */

public class PCIAuditEvent
{
    private static final String UNDEFINED = "undefined";

    private static final String DEFAULT_DATE_FORMAT = "yyyy/MM/dd";
    private static final String DEFAULT_TIME_FORMAT = "HH:mm:ss";

    private static final char DEFAULT_DELIMITER = ' ';
    private static final String DEFAULT_REPLACE_DELIMITER = "_";

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
    private String origination = null;

    /**
     * 10.3.6 "Identity or name of affected data, system component, or resource"
     */
    private String affectedResource = UNDEFINED;

    /**
     * The AuditLevel this Event belongs to.
     */
    private AuditLevel level;

    public PCIAuditEvent(
            final Date date)
    {
        this.date = new SimpleDateFormat(DEFAULT_DATE_FORMAT).format(date);
        this.time = new SimpleDateFormat(DEFAULT_TIME_FORMAT).format(date);
        this.level = AuditLevel.INFO;
    }

    public AuditLevel getLevel()
    {
        return level;
    }

    public void setLevel(
            final AuditLevel level)
    {
        this.level = level;
    }

    public String getUserId()
    {
        if (isBlank(this.userId))
        {
            return UNDEFINED;
        }

        return this.userId;
    }

    public void setUserId(
            final String userId)
    {
        this.userId = userId;
    }

    public String getEventType()
    {
        if (isBlank(this.eventType))
        {
            return UNDEFINED;
        }

        return this.eventType;
    }

    public void setEventType(
            final String eventType)
    {
        this.eventType = eventType;
    }

    public String getDate()
    {
        return date;
    }

    public String getTime()
    {
        return time;
    }

    public String getStatus()
    {
        if (isBlank(this.status))
        {
            return UNDEFINED;
        }

        return this.status;
    }

    public void setStatus(
            final String status)
    {
        this.status = status;
    }

    public String getOrigination()
    {
        if(isBlank(origination))
        {
            origination = getHostAddress();
        }

        return origination;
    }

    public void setOrigination(
            final String origination)
    {
        this.origination = origination;
    }

    public String getAffectedResource()
    {
        if (isBlank(this.affectedResource))
        {
            return UNDEFINED;
        }

        return this.affectedResource;
    }

    public void setAffectedResource(
            final String affectedResource)
    {
        this.affectedResource = affectedResource;
    }

    public CharArrayWriter toCharArrayWriter(
            final String prefix)
    {
        CharArrayWriter buffer = new CharArrayWriter();

        final char delimiter = DEFAULT_DELIMITER;
        final String replaceDelimiter = DEFAULT_REPLACE_DELIMITER;

        if(prefix != null && prefix.isEmpty() == false)
        {
            buffer.append(prefix);
        }

        buffer.append(replaceDelimiter(getUserId(), delimiter, replaceDelimiter));
        buffer.append(delimiter);
        buffer.append(replaceDelimiter(getEventType(), delimiter, replaceDelimiter));
        buffer.append(delimiter);
        buffer.append(replaceDelimiter(getDate(), delimiter, replaceDelimiter));
        buffer.append(delimiter);
        buffer.append(replaceDelimiter(getTime(), delimiter, replaceDelimiter));
        buffer.append(delimiter);
        buffer.append(replaceDelimiter(getStatus(), delimiter, replaceDelimiter));
        buffer.append(delimiter);
        buffer.append(replaceDelimiter(getOrigination(), delimiter, replaceDelimiter));
        buffer.append(delimiter);
        buffer.append(replaceDelimiter(getAffectedResource(), delimiter, replaceDelimiter));

        return buffer;
    }

    public static boolean isBlank(
            final CharSequence cs)
    {
        int strLen;
        if (cs == null || (strLen = cs.length()) == 0)
        {
            return true;
        }
        for (int i = 0; i < strLen; i++)
        {
            if (Character.isWhitespace(cs.charAt(i)) == false)
            {
                return false;
            }
        }
        return true;
    }

    private String replaceDelimiter(
            final String fieldValue,
            final char delimiter,
            final String replaceDelimiter)
    {
        if (replaceDelimiter == null || replaceDelimiter.length() < 1 ||
                fieldValue == null || fieldValue.length() < 1)
        {
            return fieldValue;
        }

        return fieldValue.replaceAll("\\" + delimiter, replaceDelimiter);
    }

    private static String getHostAddress()
    {
        List<String> addresses = new LinkedList<String>();

        Enumeration<NetworkInterface> interfaces;
        try
        {
            interfaces = NetworkInterface.getNetworkInterfaces();
        } catch (SocketException e)
        {
            return "UNKNOWN";
        }
        while(interfaces.hasMoreElements())
        {
            NetworkInterface n = (NetworkInterface) interfaces.nextElement();
            Enumeration<InetAddress> ee = n.getInetAddresses();
            while (ee.hasMoreElements())
            {
                InetAddress i = (InetAddress) ee.nextElement();
                if(i instanceof Inet4Address)
                {
                    addresses.add(((Inet4Address) i).getHostAddress());
                }
            }
        }

        for(String addr : addresses)
        {
            if(addr.startsWith("192.") == false && addr.startsWith("127.") == false)
            {
                return addr;
            }
        }

        for(String addr : addresses)
        {
            if(addr.startsWith("127.") == false)
            {
                return addr;
            }
        }

        if(addresses.size() > 0)
        {
            return addresses.get(0);
        }
        else
        {
            try
            {
                return InetAddress.getLocalHost().getHostAddress();
            } catch (UnknownHostException e)
            {
                return "UNKNOWN";
            }
        }
    }

}
