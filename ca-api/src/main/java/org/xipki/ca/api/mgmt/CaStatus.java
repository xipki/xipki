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

package org.xipki.ca.api.mgmt;

import org.xipki.util.Args;

/**
 * CA status enum.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum CaStatus {

  ACTIVE("active"),
  INACTIVE("inactive");

  private final String status;

  CaStatus(String status) {
    this.status = status;
  }

  public String getStatus() {
    return status;
  }

  public static CaStatus forName(String status) {
    Args.notNull(status, "status");
    for (CaStatus value : values()) {
      if (value.status.equalsIgnoreCase(status)) {
        return value;
      }
    }

    throw new IllegalArgumentException("invalid CaStatus " + status);
  }

}
