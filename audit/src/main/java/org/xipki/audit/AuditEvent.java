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

import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class AuditEvent {

    /**
     * The name of the application the event belongs to.
     */
    private String applicationName;

    /**
     * The name of the event type.
     */
    private String name;

    /**
     * The AuditLevel this Event belongs to.
     */
    private AuditLevel level;

    /**
     * Time-stamp when the event was saved.
     */
    private final Date timestamp;

    private AuditStatus status;

    /**
     * Duration in milliseconds.
     */
    private long duration = -1;

    /**
     * The data array belonging to the event.
     */
    private final List<AuditEventData> eventDatas = new LinkedList<>();

    public AuditEvent(final Date timestamp) {
        this.timestamp = (timestamp == null) ? new Date() : timestamp;
        this.level = AuditLevel.INFO;
    }

    public AuditLevel level() {
        return level;
    }

    public void setLevel(final AuditLevel level) {
        this.level = level;
    }

    public String name() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String applicationName() {
        return applicationName;
    }

    public void setApplicationName(final String applicationName) {
        this.applicationName = Objects.requireNonNull(applicationName,
                "applicationName must not be null");
    }

    public Date timestamp() {
        return timestamp;
    }

    public List<AuditEventData> eventDatas() {
        return Collections.unmodifiableList(eventDatas);
    }

    public AuditEventData addEventType(String type) {
        return addEventData("eventType", type);
    }

    public AuditEventData addEventData(String name, Object value) {
        return addEventData(new AuditEventData(name, value));
    }

    public AuditEventData addEventData(final AuditEventData eventData) {
        Objects.requireNonNull(eventData, "eventData must not be null");

        int idx = -1;
        for (int i = 0; i < eventDatas.size(); i++) {
            AuditEventData ed = eventDatas.get(i);
            if (ed.name().equals(eventData.name())) {
                idx = i;
                break;
            }
        }

        AuditEventData ret = null;
        if (idx != -1) {
            ret = eventDatas.get(idx);
        }
        eventDatas.add(eventData);

        return ret;
    }

    public boolean removeEventData(String eventDataName) {
        Objects.requireNonNull(eventDataName, "eventDataName must not be null");

        AuditEventData tbr = null;
        for (AuditEventData ed : eventDatas) {
            if (ed.name().equals(eventDataName)) {
                tbr = ed;
            }
        }

        boolean removed = false;
        if (tbr != null) {
            eventDatas.remove(tbr);
            removed = true;
        }

        return removed;
    }

    public AuditStatus status() {
        return status;
    }

    public void setStatus(final AuditStatus status) {
        this.status = Objects.requireNonNull(status, "status must not be null");
    }

    public void finish() {
        this.duration = System.currentTimeMillis() - timestamp.getTime();
    }

    public long duration() {
        return duration;
    }

}
