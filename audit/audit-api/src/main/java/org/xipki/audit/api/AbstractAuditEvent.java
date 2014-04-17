/*
 * Copyright 2014 xipki.org
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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractAuditEvent
{
    private static final Logger LOG = LoggerFactory.getLogger(AbstractAuditEvent.class);

    public static final String  UNDEFINED = "undefined";

    public static final String  DEFAULT_DATE_FORMAT = "yyyy/MM/dd";
    public static final String  DEFAULT_TIME_FORMAT = "HH:mm:ss";

    public static final char    DEFAULT_DELIMITER = ' ';
    public static final String  DEFAULT_REPLACE_DELIMITER = "_";

    /**
     * The ID of the event type.
     */
    protected static final AtomicLong id = new AtomicLong(0L);

    /**
     * The name of the event type.
     */
    protected String            name;

    /**
     * The AuditLevel this Event belongs to.
     */
    protected AuditLevel        level = AuditLevel.INFO;

    /**
     * Timestamp when the event was saved.
     */
    protected Date timeStamp;

    protected char getDelimiter()
    {
        return DEFAULT_DELIMITER;
    }

    protected String getReplaceDelimiter()
    {
        return DEFAULT_REPLACE_DELIMITER;
    }

    protected String getDateFormat()
    {
        return DEFAULT_DATE_FORMAT;
    }

    protected String getTimeFormat()
    {
        return DEFAULT_TIME_FORMAT;
    }

    protected String generateDate()
    {
        String date = new SimpleDateFormat(getDateFormat()).format(new Date());

        return date;
    }

    protected String generateTime()
    {
        String time = new SimpleDateFormat(getTimeFormat()).format(new Date());

        return time;
    }

    protected String[] generateDateAndTime(Date date)
    {
        String[] dateAndTime = new String[2];

        dateAndTime[0] = new SimpleDateFormat(getDateFormat()).format(date);
        dateAndTime[1] = new SimpleDateFormat(getTimeFormat()).format(date);

        return dateAndTime;
    }

    protected String generateLocalHostName()
    {
        String localHostName = UNDEFINED;

        try
        {
            localHostName = InetAddress.getLocalHost().getHostName();

        }
        catch (UnknownHostException uhe)
        {
            LOG.warn("While finding host name: ", uhe);
        }

        return localHostName;
    }

    protected String replaceDelimiter(String fieldName, String fieldValue, char delimiter,
            String replaceDelimiter)
    {
        if (replaceDelimiter == null || replaceDelimiter.length() < 1 || fieldValue == null
                || fieldValue.length() < 1)
        {
            return fieldValue;
        }

        String newFieldValue = fieldValue.replaceAll("\\" + delimiter, replaceDelimiter);

        return newFieldValue;
    }

    public long getId()
    {
        return id.longValue();
    }

    public String getName()
    {
        return name;
    }

    public void setName(final String name)
    {
        this.name = name;
    }

    public Date getTimeStamp()
    {
        return timeStamp == null ? null : (Date) timeStamp.clone();
    }

    public void setTimeStamp(final Date timeStamp)
    {
        this.timeStamp = timeStamp == null ? null : (Date) timeStamp.clone();
    }

    public AuditLevel getLevel()
    {
        return level;
    }

    public void setLevel(AuditLevel level)
    {
        this.level = level;
    }

    /**
     * <p>Checks if a CharSequence is whitespace, empty ("") or null.</p>
     *
     * <pre>
     * isBlank(null)      = true
     * isBlank("")        = true
     * isBlank(" ")       = true
     * isBlank("bob")     = false
     * isBlank("  bob  ") = false
     * </pre>
     *
     * @param cs  the CharSequence to check, may be null
     * @return {@code true} if the CharSequence is null, empty or whitespace
     */
    public static boolean isBlank(CharSequence cs) {
        int strLen;
        if (cs == null || (strLen = cs.length()) == 0) {
            return true;
        }
        for (int i = 0; i < strLen; i++) {
            if (Character.isWhitespace(cs.charAt(i)) == false) {
                return false;
            }
        }
        return true;
    }
}
