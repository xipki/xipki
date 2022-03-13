/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

import org.xipki.util.Args;

import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * Audit event.
 *
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
  private long duration;

  /**
   * The data array belonging to the event.
   */
  private final List<AuditEventData> eventDatas = new LinkedList<>();

  public AuditEvent(Date timestamp) {
    this.timestamp = (timestamp == null) ? new Date() : timestamp;
    this.level = AuditLevel.INFO;
    this.duration = -1;
  }

  public AuditLevel getLevel() {
    return level;
  }

  public void setLevel(AuditLevel level) {
    this.level = level;
  }

  public String getName() {
    return name;
  }

  public void update(AuditLevel level, AuditStatus status) {
    this.level = level;
    this.status = status;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getApplicationName() {
    return applicationName;
  }

  public void setApplicationName(String applicationName) {
    this.applicationName = Args.notNull(applicationName, "applicationName");
  }

  public Date getTimestamp() {
    return timestamp;
  }

  public List<AuditEventData> getEventDatas() {
    return Collections.unmodifiableList(eventDatas);
  }

  public AuditEventData addEventType(String type) {
    return addEventData("event_type", type);
  }

  public AuditEventData addEventData(String name, Object value) {
    return addEventData(new AuditEventData(name, value));
  }

  public AuditEventData addEventData(AuditEventData eventData) {
    Args.notNull(eventData, "eventData");

    int idx = -1;
    for (int i = 0; i < eventDatas.size(); i++) {
      final AuditEventData ed = eventDatas.get(i);
      if (ed.getName().equals(eventData.getName())) {
        idx = i;
        break;
      }
    }

    if (idx == -1) {
      eventDatas.add(eventData);
      return eventData;
    } else {
      final AuditEventData existing = eventDatas.get(idx);
      existing.addValue(eventData.getValue());
      return existing;
    }
  } // method addEventData

  public boolean removeEventData(String eventDataName) {
    Args.notNull(eventDataName, "eventDataName");

    boolean removed = false;
    for (final AuditEventData ed : eventDatas) {
      if (ed.getName().equals(eventDataName)) {
        eventDatas.remove(ed);
        removed = true;
        break;
      }
    }

    return removed;
  } // method removeEventData

  public AuditStatus getStatus() {
    return status;
  }

  public void setStatus(AuditStatus status) {
    this.status = Args.notNull(status, "status");
  }

  public void finish() {
    this.duration = System.currentTimeMillis() - timestamp.getTime();
  }

  public long getDuration() {
    return duration;
  }

  public String toTextMessage() {
    String applicationName = getApplicationName();
    if (applicationName == null) {
      applicationName = "undefined";
    }

    String name = getName();
    if (name == null) {
      name = "undefined";
    }

    StringBuilder sb = new StringBuilder(150);

    sb.append(applicationName).append(" - ").append(name);

    AuditStatus status = getStatus();
    if (status == null) {
      status = AuditStatus.UNDEFINED;
    }
    sb.append(";\tstatus: ").append(status.name());
    List<AuditEventData> eventDataArray = getEventDatas();

    long duration = getDuration();
    if (duration >= 0) {
      sb.append("\tduration: ").append(duration);
    }

    if ((eventDataArray != null) && (eventDataArray.size() > 0)) {
      for (AuditEventData m : eventDataArray) {
        if (duration >= 0 && "duration".equalsIgnoreCase(m.getName())) {
          continue;
        }

        sb.append("\t").append(m.getName()).append(": ").append(m.getValue());
      }
    }

    return sb.toString();
  } // method toTextMessage

}
