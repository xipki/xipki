// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.db;

import static org.xipki.util.Args.notBlank;

/**
 * System event.
 * @author Lijun Liao (xipki)
 *
 */
public class SystemEvent {

  private final String name;

  private final String owner;

  private final long eventTime;

  public SystemEvent(String name, String owner, long eventTime) {
    this.name = notBlank(name, "name");
    this.owner = notBlank(owner, "owner");
    this.eventTime = eventTime;
  }

  public String getName() {
    return name;
  }

  public String getOwner() {
    return owner;
  }

  public long getEventTime() {
    return eventTime;
  }

} // class SystemEvent
