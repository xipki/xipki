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
 * TODO.
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

  public void setName(String name) {
    this.name = name;
  }

  public String getApplicationName() {
    return applicationName;
  }

  public void setApplicationName(String applicationName) {
    this.applicationName = Objects.requireNonNull(applicationName,
        "applicationName may not be null");
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
    Objects.requireNonNull(eventData, "eventData may not be null");

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
  }

  public boolean removeEventData(String eventDataName) {
    Objects.requireNonNull(eventDataName, "eventDataName may not be null");

    boolean removed = false;
    for (final AuditEventData ed : eventDatas) {
      if (ed.getName().equals(eventDataName)) {
        eventDatas.remove(ed);
        removed = true;
        break;
      }
    }

    return removed;
  }

  public AuditStatus getStatus() {
    return status;
  }

  public void setStatus(AuditStatus status) {
    this.status = Objects.requireNonNull(status, "status may not be null");
  }

  public void finish() {
    this.duration = System.currentTimeMillis() - timestamp.getTime();
  }

  public long getDuration() {
    return duration;
  }

}
