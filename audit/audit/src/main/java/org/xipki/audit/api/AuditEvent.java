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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Lijun Liao
 */

public class AuditEvent
{

    /**
     * The name of the application the event belongs to.
     */
    private String applicationName;

    /**
     * The data array belonging to the event.
     */
    private final List<AuditEventData> eventDatas = new LinkedList<AuditEventData>();

    /**
     * The name of the event type.
     */
    private String name;

    /**
     * The AuditLevel this Event belongs to.
     */
    private AuditLevel level;

    /**
     * Timestamp when the event was saved.
     */
    private final Date timestamp;

    private AuditStatus status;

    private long duration = -1;

    private final List<AuditChildEvent> childAuditEvents = new LinkedList<AuditChildEvent>();

    public AuditEvent(
            final Date timestamp)
    {
        this.timestamp = (timestamp == null) ? new Date() : timestamp;
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

    public String getName()
    {
        return name;
    }

    public void setName(
            final String name)
    {
        this.name = name;
    }

    public String getApplicationName()
    {
        return applicationName;
    }

    public void setApplicationName(
            final String applicationName)
    {
        this.applicationName = applicationName;
    }

    public Date getTimestamp()
    {
        return timestamp;
    }

    public List<AuditEventData> getEventDatas()
    {
        return Collections.unmodifiableList(eventDatas);
    }

    public AuditEventData addEventData(
            final AuditEventData eventData)
    {
        int idx = -1;
        for(int i = 0; i < eventDatas.size(); i++)
        {
            AuditEventData ed = eventDatas.get(i);
            if(ed.getName().equals(eventData.getName()))
            {
                idx = i;
                break;
            }
        }

        AuditEventData ret = null;
        if(idx != -1)
        {
            ret = eventDatas.get(idx);
        }
        eventDatas.add(eventData);

        for(AuditChildEvent cae : childAuditEvents)
        {
            cae.removeEventData(eventData.getName());
        }

        return ret;
    }

    public AuditStatus getStatus()
    {
        return status;
    }

    public void setStatus(
            final AuditStatus status)
    {
        this.status = status;
    }

    public void addChildAuditEvent(
            final AuditChildEvent childAuditEvent)
    {
        childAuditEvents.add(childAuditEvent);
    }

    public boolean containsChildAuditEvents()
    {
        return childAuditEvents.isEmpty() == false;
    }

    public List<AuditEvent> expandAuditEvents()
    {
        int size = childAuditEvents.size();
        if(size == 0)
        {
            return Arrays.asList(this);
        }

        List<AuditEvent> expandedEvents = new ArrayList<AuditEvent>(size);
        for(AuditChildEvent child : childAuditEvents)
        {
            AuditEvent event = new AuditEvent(timestamp);
            event.setApplicationName(applicationName);
            event.setName(name);

            if(child.getLevel() != null)
            {
                event.setLevel(child.getLevel());
            }
            else
            {
                event.setLevel(level);
            }

            if(child.getStatus() != null)
            {
                event.setStatus(child.getStatus());
            }
            else
            {
                event.setStatus(status);
            }

            for(AuditEventData eventData : eventDatas)
            {
                event.addEventData(eventData);
            }

            for(AuditEventData eventData : child.getEventDatas())
            {
                event.addEventData(eventData);
            }

            event.setDuration(duration);

            expandedEvents.add(event);
        }

        return expandedEvents;
    }

    public long getDuration()
    {
        return duration;
    }

    public void setDuration(
            final long duration)
    {
        this.duration = duration;
    }
}
