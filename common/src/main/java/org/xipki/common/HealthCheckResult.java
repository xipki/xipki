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

package org.xipki.common;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HealthCheckResult {

  private String name;

  private boolean healthy;

  private Map<String, Object> statuses = new ConcurrentHashMap<>();

  private List<HealthCheckResult> childChecks = new LinkedList<>();

  /**
   * TODO.
   * @param name Name of the check result.
   */
  public HealthCheckResult(String name) {
    this.name = ParamUtil.requireNonBlank("name", name);
  }

  public void setHealthy(boolean healthy) {
    this.healthy = healthy;
  }

  public void clearStatuses() {
    this.statuses.clear();
  }

  public Object status(String statusName) {
    return (statusName == null) ? null : statuses.get(statusName);
  }

  public void clearChildChecks() {
    this.childChecks.clear();
  }

  public void addChildCheck(HealthCheckResult childCheck) {
    ParamUtil.requireNonNull("childCheck", childCheck);
    this.childChecks.add(childCheck);
  }

  public Set<String> statusNames() {
    return statuses.keySet();
  }

  public boolean isHealthy() {
    return healthy;
  }

  public Map<String, Object> statuses() {
    return Collections.unmodifiableMap(statuses);
  }

  public String toJsonMessage(boolean pretty) {
    return toJsonMessage(0, pretty);
  }

  private String toJsonMessage(int level, boolean pretty) {
    // Non root check requires always a name
    StringBuilder sb = new StringBuilder(1000);
    if (pretty) {
      addIndent(sb, level);
    }
    if (level > 0) {
      sb.append("\"").append(name).append("\":");
    }
    sb.append("{");

    boolean lastElement = true;
    if (lastElement && CollectionUtil.isNonEmpty(statuses)) {
      lastElement = false;
    }
    if (lastElement && CollectionUtil.isNonEmpty(childChecks)) {
      lastElement = false;
    }
    append(sb, "healthy", healthy, level + 1, pretty, lastElement);

    Set<String> names = statuses.keySet();
    int size = names.size();
    int count = 0;
    for (String entry : names) {
      count++;
      append(sb, entry, statuses.get(entry), level + 1, pretty,
          CollectionUtil.isEmpty(childChecks) && count == size);
    }

    if (CollectionUtil.isNonEmpty(childChecks)) {
      if (pretty) {
        sb.append("\n");
        addIndent(sb, level + 1);
      }

      sb.append("\"checks\":{");
      if (pretty) {
        sb.append("\n");
      }

      int childChecksSize = childChecks.size();
      for (int i = 0; i < childChecksSize; i++) {
        HealthCheckResult childCheck = childChecks.get(i);
        if (i > 0 && pretty) {
          sb.append("\n");
        }
        sb.append(childCheck.toJsonMessage(level + 2, pretty));
        if (i < childChecksSize - 1) {
          sb.append(",");
        }
      }

      if (pretty) {
        sb.append("\n");
        addIndent(sb, level + 1);
      }
      sb.append("}");
    }

    if (pretty) {
      sb.append("\n");
      addIndent(sb, level);
    }
    sb.append("}");
    return sb.toString();
  } // method toJsonMessage

  private static void append(StringBuilder sb, String name, Object value,
      int level, boolean pretty, boolean lastElement) {
    if (pretty) {
      sb.append("\n");
      addIndent(sb, level);
    }
    sb.append("\"").append(name).append("\":");

    if (value == null) {
      sb.append("null");
    } else if (value instanceof Number) {
      sb.append(value);
    } else if (value instanceof Boolean) {
      sb.append(value);
    } else {
      sb.append("\"").append(value).append("\"");
    }

    if (!lastElement) {
      sb.append(",");
    }
  } // method append

  private static void addIndent(StringBuilder buffer, int level) {
    if (level == 0) {
      return;
    }

    for (int i = 0; i < level; i++) {
      buffer.append("    ");
    }
  }

  public static HealthCheckResult getInstanceFromJsonMessage(String name, String jsonMessage) {
    // remove white spaces and line breaks
    String jsonMsg = jsonMessage.replaceAll(" |\t|\r|\n", "");
    if (!jsonMsg.startsWith("{\"healthy\":")) {
      throw new IllegalArgumentException("invalid healthcheck message");
    }

    int startIdx = "{\"healthy\":".length();
    int endIdx = jsonMsg.indexOf(',', startIdx);
    boolean containsChildChecks = true;
    if (endIdx == -1) {
      endIdx = jsonMsg.indexOf('}', startIdx);
      containsChildChecks = false;
    }

    if (endIdx == -1) {
      throw new IllegalArgumentException("invalid healthcheck message");
    }

    String str = jsonMsg.substring(startIdx, endIdx);

    boolean healthy;
    if ("true".equalsIgnoreCase(str) || "false".equalsIgnoreCase(str)) {
      healthy = Boolean.parseBoolean(str);
    } else {
      throw new IllegalArgumentException("invalid healthcheck message");
    }

    HealthCheckResult result = new HealthCheckResult(name);
    result.setHealthy(healthy);

    if (!containsChildChecks) {
      return result;
    }

    if (!jsonMsg.startsWith("\"checks\":", endIdx + 1)) {
      return result;
    }

    String checksBlock = getBlock(jsonMsg, endIdx + 1 + "\"checks\":".length());
    String block = checksBlock.substring(1, checksBlock.length() - 1);
    Map<String, String> childBlocks = getChildBlocks(block);
    for (String childBlockName : childBlocks.keySet()) {
      HealthCheckResult childResult = getInstanceFromJsonMessage(childBlockName,
          childBlocks.get(childBlockName));
      result.addChildCheck(childResult);
    }

    return result;
  }

  private static Map<String, String> getChildBlocks(String block) {
    Map<String, String> childBlocks = new HashMap<>();

    int offset = 0;
    while (true) {
      int idx = block.indexOf('"', offset + 1);
      String blockName = block.substring(offset + 1, idx);
      String blockValue = getBlock(block, offset + blockName.length() + 3);
      childBlocks.put(blockName, blockValue);

      offset += blockName.length() + 4 + blockValue.length();
      if (offset >= block.length() - 1) {
        break;
      }
    }

    return childBlocks;
  } // method getInstanceFromJsonMessage

  private static String getBlock(String text, int offset) {
    if (!text.startsWith("{", offset)) {
      throw new IllegalArgumentException("invalid text: '" + text + "'");
    }

    StringBuilder sb = new StringBuilder("{");
    final int len = text.length();
    if (len < 2) {
      throw new IllegalArgumentException("invalid text: '" + text + "'");
    }

    char ch;
    int im = 0;
    for (int i = offset + 1; i < len; i++) {
      ch = text.charAt(i);
      sb.append(ch);

      if (ch == '{') {
        im++;
      } else if (ch == '}') {
        if (im == 0) {
          return sb.toString();
        } else {
          im--;
        }
      } // end if
    } // end for

    throw new IllegalArgumentException("invalid text: '" + text + "'");
  } // method getBlock

}
