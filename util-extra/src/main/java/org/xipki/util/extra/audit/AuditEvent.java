// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.audit;

import org.slf4j.Logger;
import org.xipki.util.codec.Args;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Audit event.
 *
 * @author Lijun Liao (xipki)
 */

public class AuditEvent {

  /**
   * The name of the application the event belongs to.
   */
  private final String applicationName;

  /**
   * The AuditLevel this Event belongs to.
   */
  private AuditLevel level;

  /**
   * Time-stamp when the event was saved.
   */
  private final Instant timestamp;

  private AuditStatus status;

  /**
   * Duration.
   */
  private Duration duration;

  /**
   * The data array belonging to the event.
   */
  private final List<AuditEventData> eventDatas = new LinkedList<>();

  public AuditEvent(String applicationName) {
    this(applicationName, null);
  }

  public AuditEvent(String applicationName, Instant timestamp) {
    this.applicationName = applicationName == null ? "undefined"
        : applicationName;
    this.timestamp = (timestamp == null) ? Instant.now() : timestamp;
    this.level = AuditLevel.INFO;
    this.duration = null;
  }

  public AuditLevel level() {
    return (status == AuditStatus.FAILED && AuditLevel.INFO == level)
        ? AuditLevel.WARN : level;
  }

  public void setLevel(AuditLevel level) {
    this.level = level;
  }

  public void update(AuditLevel level, AuditStatus status) {
    this.level = level;
    this.status = status;
  }

  public String applicationName() {
    return applicationName;
  }

  public Instant timestamp() {
    return timestamp;
  }

  public List<AuditEventData> eventDatas() {
    return Collections.unmodifiableList(eventDatas);
  }

  public void setEventType(String type) {
    setEventData("event_type", type);
  }

  public AuditEventData addEventType(String type) {
    return addEventData("event_type", type);
  }

  public void setEventData(String name, Object value) {
    Args.notNull(name, "name");
    if (value == null) {
      value = "null";
    }

    int idx = -1;
    for (int i = 0; i < eventDatas.size(); i++) {
      final AuditEventData ed = eventDatas.get(i);
      if (ed.name().equals(name)) {
        idx = i;
        break;
      }
    }

    if (idx != -1) {
      eventDatas.remove(idx);
    }
    eventDatas.add(new AuditEventData(name, value));
  }

  public AuditEventData addEventData(String name, Object value) {
    return addEventData(new AuditEventData(name, value));
  }

  public AuditEventData addEventData(AuditEventData eventData) {
    Args.notNull(eventData, "eventData");

    int idx = -1;
    for (int i = 0; i < eventDatas.size(); i++) {
      final AuditEventData ed = eventDatas.get(i);
      if (ed.name().equals(eventData.name())) {
        idx = i;
        break;
      }
    }

    if (idx == -1) {
      eventDatas.add(eventData);
      return eventData;
    } else {
      final AuditEventData existing = eventDatas.get(idx);
      existing.addValue(eventData.value());
      return existing;
    }
  } // method addEventData

  public boolean removeEventData(String eventDataName) {
    Args.notNull(eventDataName, "eventDataName");

    boolean removed = false;
    for (final AuditEventData ed : eventDatas) {
      if (ed.name().equals(eventDataName)) {
        eventDatas.remove(ed);
        removed = true;
        break;
      }
    }

    return removed;
  }

  public AuditStatus status() {
    return status;
  }

  public void setStatus(AuditStatus status) {
    Args.notNull(status, "status");
    if (this.status != status && this.status != AuditStatus.FAILED) {
      this.status = status;
    }
  }

  public void finish() {
    this.duration = Duration.between(timestamp, Instant.now());
  }

  public Duration duration() {
    return duration;
  }

  public String toTextMessage() {
    StringBuilder sb = new StringBuilder(150);

    sb.append(applicationName);

    AuditStatus status = status();
    if (status == null) {
      status = AuditStatus.UNDEFINED;
    }
    sb.append(";\tstatus: ").append(status.name());
    List<AuditEventData> eventDataArray = eventDatas();

    Duration duration = duration();
    if (duration != null) {
      sb.append("\tduration: ").append(duration.toMillis());
    }

    if ((eventDataArray != null) && (!eventDataArray.isEmpty())) {
      for (AuditEventData m : eventDataArray) {
        if ("duration".equalsIgnoreCase(m.name())) {
          continue;
        }

        sb.append("\t").append(m.name()).append(": ").append(m.value());
      }
    }

    return sb.toString();
  }

  public void log(Logger log) {
    AuditLevel level = level();
    if (level == AuditLevel.ERROR) {
      log.error(toTextMessage());
    } else if (level == AuditLevel.WARN) {
      log.warn(toTextMessage());
    } else {
      log.info(toTextMessage());
    }
  }

}
