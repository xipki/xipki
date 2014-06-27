/*
 * Copyright (c) 2014 Lijun Liao
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

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * This file is copied from PCSSyslogMessage from syslog4j.org
 *
 * PCISyslogMessage provides support for audit trails defined by section
 * 10.3 of the PCI Data Security Standard (PCI DSS) versions 1.1 and 1.2.
 *
 * <p>More information on the PCI DSS specification is available here:</p>
 *
 * <p>https://www.pcisecuritystandards.org/security_standards/pci_dss.shtml</p>
 *
 * <p>The PCI DSS specification is Copyright 2008 PCI Security Standards
 * Council LLC.</p>
 *
 * <p>Syslog4j is licensed under the Lesser GNU Public License v2.1.  A copy
 * of the LGPL license is available in the META-INF folder in all
 * distributions of Syslog4j and in the base directory of the "doc" ZIP.</p>
 *
 * @author &lt;syslog4j@productivity.org&gt;
 * @version $Id: PCISyslogMessage.java,v 1.3 2008/11/14 04:32:00 cvs Exp $
 *
 * @author Lijun Liao
 */

public class PCIAuditEvent
{
    public static final String UNDEFINED = "undefined";

    public static final String DEFAULT_DATE_FORMAT = "yyyy/MM/dd";
    public static final String DEFAULT_TIME_FORMAT = "HH:mm:ss";

    public static final char DEFAULT_DELIMITER = ' ';
    public static final String DEFAULT_REPLACE_DELIMITER = "_";

    public static final String USER_ID           = "userId";
    public static final String EVENT_TYPE        = "eventType";
    public static final String DATE              = "date";
    public static final String TIME              = "time";
    public static final String STATUS            = "status";
    public static final String ORIGINATION       = "origination";
    public static final String AFFECTED_RESOURCE = "affectedResource";

    /**
     * 10.3.1 "User Identification"
     */
    private String userId           = UNDEFINED;

    /**
     * 10.3.2 "Type of event"
     */
    private String eventType        = UNDEFINED;

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
    private String status           = UNDEFINED;

    /**
     * 10.3.5 "Origination of Event"
     */
    private String origination      = null;

    /**
     * 10.3.6 "Identity or name of affected data, system component, or resource"
     */
    private String affectedResource = UNDEFINED;

    /**
     * The AuditLevel this Event belongs to.
     */
    private AuditLevel level;

    public PCIAuditEvent(Date date)
    {
        this.date = new SimpleDateFormat(DEFAULT_DATE_FORMAT).format(date);
        this.time = new SimpleDateFormat(DEFAULT_TIME_FORMAT).format(date);
        this.level = AuditLevel.INFO;
    }

    public AuditLevel getLevel()
    {
        return level;
    }

    public void setLevel(AuditLevel level)
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

    public void setUserId(String userId)
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

    public void setEventType(String eventType)
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

    public void setStatus(String status)
    {
        this.status = status;
    }

    public String getOrigination()
    {
        return this.origination;
    }

    public void setOrigination(String origination)
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

    public void setAffectedResource(String affectedResource)
    {
        this.affectedResource = affectedResource;
    }

    public String createMessage()
    {
        StringBuffer buffer = new StringBuffer();

        char delimiter = DEFAULT_DELIMITER;
        String replaceDelimiter = DEFAULT_REPLACE_DELIMITER;

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

        return buffer.toString();
    }

    public static boolean isBlank(CharSequence cs)
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

    private String replaceDelimiter(String fieldValue,
            char delimiter, String replaceDelimiter)
    {
        if (replaceDelimiter == null || replaceDelimiter.length() < 1 ||
                fieldValue == null || fieldValue.length() < 1)
        {
            return fieldValue;
        }

        String newFieldValue = fieldValue.replaceAll("\\" + delimiter, replaceDelimiter);

        return newFieldValue;
    }

}
