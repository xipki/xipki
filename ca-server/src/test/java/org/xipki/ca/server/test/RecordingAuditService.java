// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.test;

import org.xipki.codec.util.ConfPairs;
import org.xipki.util.audit.AuditEvent;
import org.xipki.util.audit.AuditEventData;
import org.xipki.util.audit.AuditService;
import org.xipki.util.audit.Audits;
import org.xipki.util.audit.PciAuditEvent;

import java.util.ArrayList;
import java.util.List;

/**
 * Audit service which records the audit events, to check them in tests. Install it with
 * {@link #install()}.
 *
 * @author Lijun Liao (xipki)
 */
public class RecordingAuditService implements AuditService {

  private static final List<AuditEvent> EVENTS = new ArrayList<>();

  public RecordingAuditService() {
  }

  /** Replaces the audit service of {@link Audits} by a new {@link RecordingAuditService}. */
  public static void install() {
    Audits.init("java:" + RecordingAuditService.class.getName(), new ConfPairs(), null);
    clear();
  }

  /** Restores the noop audit service. */
  public static void uninstall() {
    Audits.init("noop", new ConfPairs(), null);
  }

  public static void clear() {
    synchronized (EVENTS) {
      EVENTS.clear();
    }
  }

  /** Returns the recorded events with the given event type. */
  public static List<AuditEvent> events(String eventType) {
    List<AuditEvent> ret = new ArrayList<>();
    synchronized (EVENTS) {
      for (AuditEvent event : EVENTS) {
        if (eventType.equals(eventData(event, "event_type"))) {
          ret.add(event);
        }
      }
    }
    return ret;
  }

  /** Returns the value of the event data with the given name, or {@code null}. */
  public static String eventData(AuditEvent event, String name) {
    for (AuditEventData data : event.eventDatas()) {
      if (data.name().equals(name)) {
        return data.value();
      }
    }
    return null;
  }

  @Override
  public void init(ConfPairs conf, String basedir) {
  }

  @Override
  public void logEvent(AuditEvent event) {
    synchronized (EVENTS) {
      EVENTS.add(event);
    }
  }

  @Override
  public void logEvent(PciAuditEvent event) {
  }

  @Override
  public void close() {
  }

}
