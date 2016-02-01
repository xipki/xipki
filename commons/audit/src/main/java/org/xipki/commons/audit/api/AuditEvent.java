/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.audit.api;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Lijun Liao
 */

public class AuditEvent {

    /**
     * The name of the application the event belongs to.
     */
    private String applicationName;

    /**
     * The data array belonging to the event.
     */
    private final List<AuditEventData> eventDatas = new LinkedList<>();

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

    private final List<AuditChildEvent> childAuditEvents = new LinkedList<>();

    public AuditEvent(
            final Date timestamp) {
        this.timestamp = (timestamp == null)
                ? new Date()
                : timestamp;
        this.level = AuditLevel.INFO;
    }

    public AuditLevel getLevel() {
        return level;
    }

    public void setLevel(
            final AuditLevel level) {
        this.level = level;
    }

    public String getName() {
        return name;
    }

    public void setName(
            final String name) {
        this.name = name;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(
            final String applicationName) {
        this.applicationName = applicationName;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public List<AuditEventData> getEventDatas() {
        return Collections.unmodifiableList(eventDatas);
    }

    public AuditEventData addEventData(
            final AuditEventData eventData) {
        int idx = -1;
        for (int i = 0; i < eventDatas.size(); i++) {
            AuditEventData ed = eventDatas.get(i);
            if (ed.getName().equals(eventData.getName())) {
                idx = i;
                break;
            }
        }

        AuditEventData ret = null;
        if (idx != -1) {
            ret = eventDatas.get(idx);
        }
        eventDatas.add(eventData);

        for (AuditChildEvent cae : childAuditEvents) {
            cae.removeEventData(eventData.getName());
        }

        return ret;
    }

    public AuditStatus getStatus() {
        return status;
    }

    public void setStatus(
            final AuditStatus status) {
        this.status = status;
    }

    public void addChildAuditEvent(
            final AuditChildEvent childAuditEvent) {
        childAuditEvents.add(childAuditEvent);
    }

    public boolean containsChildAuditEvents() {
        return !childAuditEvents.isEmpty();
    }

    public List<AuditEvent> expandAuditEvents() {
        int size = childAuditEvents.size();
        if (size == 0) {
            return Arrays.asList(this);
        }

        List<AuditEvent> expandedEvents = new ArrayList<>(size);
        for (AuditChildEvent child : childAuditEvents) {
            AuditEvent event = new AuditEvent(timestamp);
            event.setApplicationName(applicationName);
            event.setName(name);

            if (child.getLevel() != null) {
                event.setLevel(child.getLevel());
            } else {
                event.setLevel(level);
            }

            if (child.getStatus() != null) {
                event.setStatus(child.getStatus());
            } else {
                event.setStatus(status);
            }

            for (AuditEventData eventData : eventDatas) {
                event.addEventData(eventData);
            }

            for (AuditEventData eventData : child.getEventDatas()) {
                event.addEventData(eventData);
            }

            event.setDuration(duration);
            expandedEvents.add(event);
        }

        return expandedEvents;
    }

    public long getDuration() {
        return duration;
    }

    public void setDuration(
            final long duration) {
        this.duration = duration;
    }

}
