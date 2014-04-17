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

import java.io.Serializable;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Provides a default implementation of {@link PCIAuditEvent}  that is logged or to be logged in the future.
 *
 * {@link PCIAuditEvent} provides support for audit trails defined by section
 * 10.3 of the PCI Data Security Standard (PCI DSS) version 3.0 Nov. 2013.
 *
 * <p>More information on the PCI DSS specification is available here:</p>
 *
 * <p><a href="https://www.pcisecuritystandards.org/security_standards/pci_dss.shtml">PCI_DSS</a></p>
 *
 * <p>The PCI DSS specification is Copyright 2006-2013 PCI Security Standards
 * Council LLC.</p>
 *
 * $Id$
 *
 */
public class PCIAuditEvent extends AuditEvent
{
    public static final String USER_ID              = "userId";
    public static final String EVENT_TYPE           = "eventType";
    public static final String DATE                 = "date";
    public static final String TIME                 = "time";
    public static final String STATUS               = "status";
    public static final String ORIGINATION          = "origination";
    public static final String AFFECTED_RESOURCE    = "affectedResource";

    public static final String AUDIT_LEVEL          = "level";
    public static final String APPLICATION_NAME     = "applicationName";
    public static final String EVENT_DATA           = "eventData";
    public static final String EVENT_NAME           = "eventName";

    public static final String SYSTEM_USER          = "SYSTEM";

    // 10.3.1 "User Identification"
    protected String          userId           = UNDEFINED;

    // 10.3.2 "Type of event"
    protected String          eventType        = UNDEFINED;

    // 10.3.3 "Date and time" (date)
    protected String          date             = null;

    // 10.3.3 "Date and time" (time)
    protected String          time             = null;

    // 10.3.4 "Success or failure indication"
    protected String          status           = UNDEFINED;

    // 10.3.5 "Origination of Event"
    protected String          origination      = null;

    // 10.3.6 "Identity or name of affected data, system component, or resource"
    protected String          affectedResource = UNDEFINED;

    /**
     * Default constructor for jaxb.
     */
    public PCIAuditEvent()
    {
        id.getAndIncrement();
    }

    public PCIAuditEvent(PCIAuditEvent event)
    {
        init(event);
    }

    public PCIAuditEvent(Map<String, Serializable> fields)
    {
        init(fields);
    }

    /**
     * Constructor for setting initial parameters.
     *
     * @param name
     *            Event name.
     * @param applicationName
     *            Application name.
     * @param timeStamp
     *            Timestamp when the event was saved.
     * @param eventDatas
     *            The event data array for this event.
     */
    public PCIAuditEvent(final String name, final String applicationName, final Date timeStamp,
                 final AuditEventData[] eventDatas)
    {
        id.getAndIncrement();
        setName(name);
        setApplicationName(applicationName);
        setTimeStamp(timeStamp);
        setEventDatas(eventDatas);
    }


    public PCIAuditEvent(String userId, String eventType, String status, String affectedResource)
    {
        this.userId = userId;
        this.eventType = eventType;
        this.status = status;
        this.affectedResource = affectedResource;
    }

    public PCIAuditEvent(String userId, String eventType, String status, String origination,
            String affectedResource)
    {
        this.userId = userId;
        this.eventType = eventType;
        this.status = status;
        this.origination = origination;
        this.affectedResource = affectedResource;
    }

    public PCIAuditEvent(String userId, String eventType, String date, String time,
            String status, String affectedResource)
    {
        this.userId = userId;
        this.eventType = eventType;
        this.date = date;
        this.time = time;
        this.status = status;
        this.affectedResource = affectedResource;
    }

    public PCIAuditEvent(String userId, String eventType, String date, String time,
            String status, String origination, String affectedResource)
    {
        this.userId = userId;
        this.eventType = eventType;
        this.date = date;
        this.time = time;
        this.status = status;
        this.origination = origination;
        this.affectedResource = affectedResource;
    }

    public PCIAuditEvent(String userId, String eventType, Date date, String status,
            String affectedResource)
    {
        this.userId = userId;
        this.eventType = eventType;

        String[] dateAndTime = generateDateAndTime(date);
        this.date = dateAndTime[0];
        this.time = dateAndTime[1];

        this.status = status;
        this.affectedResource = affectedResource;
    }

    public PCIAuditEvent(String userId, String eventType, Date date, String status,
            String origination, String affectedResource)
    {

        this.userId = userId;
        this.eventType = eventType;

        String[] dateAndTime = generateDateAndTime(date);
        this.date = dateAndTime[0];
        this.time = dateAndTime[1];

        this.status = status;
        this.origination = origination;
        this.affectedResource = affectedResource;
    }


    protected void init(PCIAuditEvent event)
    {
        id.getAndIncrement();

        setUserId(event.getUserId());
        setEventType(event.getEventType());
        setDate(event.getDate());
        setTime(event.getTime());
        setStatus(event.getStatus());
        setOrigination(event.getOrigination());
        setAffectedResource(event.getAffectedResource());
        setLevel(event.getLevel());
        setName(event.getName());
        setApplicationName(event.getApplicationName());
        setEventDatas(eventDatas);
    }


    protected void init(Map<String, Serializable> fields)
    {
        id.getAndIncrement();

        if (fields.containsKey(APPLICATION_NAME))
        {
            this.applicationName = (String) fields.get(APPLICATION_NAME);
        }

        if (fields.containsKey(EVENT_NAME))
        {
            this.name = (String) fields.get(EVENT_NAME);
        }

        if (fields.containsKey(EVENT_DATA) && fields.get(EVENT_DATA) instanceof AuditEventData[])
        {
            setEventDatas((AuditEventData[]) fields.get(EVENT_DATA));
        }

        if (fields.containsKey(AUDIT_LEVEL) && fields.get(AUDIT_LEVEL) instanceof AuditLevel)
        {
            this.level = (AuditLevel) fields.get(AUDIT_LEVEL);
        }

        if (fields.containsKey(USER_ID))
        {
            this.userId = (String) fields.get(USER_ID);
        }

        if (fields.containsKey(EVENT_TYPE))
        {
            this.eventType = (String) fields.get(EVENT_TYPE);
        }

        if (fields.containsKey(DATE) && fields.get(DATE) instanceof String)
        {
            this.date = (String) fields.get(DATE);
        }

        if (fields.containsKey(DATE) && fields.get(DATE) instanceof Date)
        {
            setDate((Date) fields.get(DATE));
        }

        if (fields.containsKey(TIME))
        {
            this.time = (String) fields.get(TIME);
        }

        if (fields.containsKey(STATUS))
        {
            this.status = (String) fields.get(STATUS);
        }

        if (fields.containsKey(ORIGINATION))
        {
            this.origination = (String) fields.get(ORIGINATION);
        }

        if (fields.containsKey(AFFECTED_RESOURCE))
        {
            this.affectedResource = (String) fields.get(AFFECTED_RESOURCE);
        }
    }


    public String getUserId()
    {
        if (isBlank(this.userId))
        {
            return SYSTEM_USER;
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
        if (isBlank(this.date))
        {
            String dateNow = generateDate();
            return dateNow;
        }

        return this.date;
    }

    public void setDate(String date)
    {
        this.date = date;
    }

    public void setDate(Date date)
    {
        String[] d = generateDateAndTime(date);

        this.date = d[0];
        this.time = d[1];
    }

    public String getTime()
    {
        if (isBlank(this.time))
        {
            String timeNow = generateTime();

            return timeNow;
        }

        return this.time;
    }

    public void setTime(String time)
    {
        this.time = time;
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
        if (isBlank(this.origination))
        {
            String originationHere = generateLocalHostName();

            return originationHere;
        }

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

    @Override
    public String toString()
    {
        final int maxLen = 10;
        List<AuditEventData> eventDatasText;
        if(eventDatas != null)
        {
            eventDatasText = Arrays.asList(eventDatas).subList(0, Math.min(eventDatas.length, maxLen));
        }
        else
        {
            eventDatasText = null;
        }

        StringBuilder builder = new StringBuilder();
        builder.append("PCIAuditEvent ")
                .append("[userId=").append(userId)
                .append(", eventType=").append(eventType)
                .append(", date=").append(date)
                .append(", time=").append(time)
                .append(", status=").append(status)
                .append(", origination=").append(origination)
                .append(", affectedResource=").append(affectedResource)
                .append(", applicationName=").append(applicationName)
                .append(", eventDatas=").append(eventDatasText)
                .append(", name=").append(name)
                .append(", level=").append(level)
                .append(", timeStamp=").append(timeStamp)
                .append(", id=").append(id).append("]");
        return builder.toString();
    }
}
