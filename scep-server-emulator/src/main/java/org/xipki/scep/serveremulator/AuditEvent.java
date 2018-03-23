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

package org.xipki.scep.serveremulator;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;

/**
 * TODO.
 * @author Lijun Liao
 */

public class AuditEvent {

  public static enum AuditLevel {

    ERROR,
    INFO;

  }

  /**
   * The name of the event type.
   */
  private String name;

  /**
   * The AuditLevel this Event belongs to.
   */
  private AuditLevel level;

  /**
   * The data array belonging to the event.
   */
  private final Map<String, String> eventDatas = new HashMap<>();

  public AuditEvent() {
    this.level = AuditLevel.INFO;
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

  public Map<String, String> getEventDatas() {
    return Collections.unmodifiableMap(eventDatas);
  }

  public void putEventData(String name, Object value) {
    eventDatas.put(name, value.toString());
  }

  public void log(Logger log) {
    StringBuilder sb = new StringBuilder();
    for (String name : eventDatas.keySet()) {
      sb.append(name).append(": ").append(eventDatas.get(name)).append(" | ");
    }

    int len = sb.length();
    if (len > 2) {
      sb.delete(len - 2, len);
    }

    if (level == AuditLevel.ERROR) {
      log.error("{} | {}", name, sb);
    } else {
      log.info("{} | {}", name, sb);
    }
  }

}
