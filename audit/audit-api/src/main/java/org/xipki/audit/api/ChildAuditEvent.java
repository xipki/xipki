/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.audit.api;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Lijun Liao
 */

public class ChildAuditEvent
{
    /**
     * The data array belonging to the event.
     */
    private final List<AuditEventData> eventDatas = new LinkedList<>();

    /**
     * The AuditLevel this Event belongs to.
     */
    private AuditLevel level;

    private AuditStatus status;

    public ChildAuditEvent()
    {
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

    public List<AuditEventData> getEventDatas()
    {
        return Collections.unmodifiableList(eventDatas);
    }

    public AuditEventData removeEventData(String eventDataName)
    {
        AuditEventData tbr = null;
        for(AuditEventData ed : eventDatas)
        {
            if(ed.getName().equals(eventDataName))
            {
                tbr = ed;
            }
        }
        if(tbr != null)
        {
            eventDatas.remove(tbr);
        }

        return tbr;
    }

    public AuditEventData addEventData(AuditEventData eventData)
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
        return ret;
    }

    public AuditStatus getStatus()
    {
        return status;
    }

    public void setStatus(AuditStatus status)
    {
        this.status = status;
    }

}
