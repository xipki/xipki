// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server;

import org.xipki.util.codec.Args;

/**
 * System event.
 * @author Lijun Liao (xipki)
 */
public class SystemEvent {

  private final String name;

  private final String owner;

  private final long eventTime;

  public SystemEvent(String name, String owner, long eventTime) {
    this.name = Args.notBlank(name, "name");
    this.owner = Args.notBlank(owner, "owner");
    this.eventTime = eventTime;
  }

  public String name() {
    return name;
  }

  public String owner() {
    return owner;
  }

  public long eventTime() {
    return eventTime;
  }

} // class SystemEvent
