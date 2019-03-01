/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.util;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public boolean isHealthy() {
    return healthy;
  }

  public void setHealthy(boolean healthy) {
    this.healthy = healthy;
  }

  public Map<String, Object> getStatuses() {
    return statuses;
  }

  public void setStatuses(Map<String, Object> statuses) {
    this.statuses = statuses;
  }

  public List<HealthCheckResult> getChildChecks() {
    return childChecks;
  }

  public void setChildChecks(List<HealthCheckResult> childChecks) {
    this.childChecks = childChecks;
  }

  public void addChildCheck(HealthCheckResult childCheck) {
    if (childChecks == null) {
      childChecks = new LinkedList<>();
    }
    childChecks.add(childCheck);
  }
}
