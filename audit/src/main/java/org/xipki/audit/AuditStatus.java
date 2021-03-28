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

/**
 * Audit status.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum AuditStatus {

  SUCCESSFUL,
  FAILED,
  UNDEFINED;

  AuditStatus() {
  }

  public static AuditStatus forName(final String name) {
    Args.notNull(name, "name");
    for (final AuditStatus v : values()) {
      if (v.name().equals(name)) {
        return v;
      }
    }
    throw new IllegalArgumentException("invalid AuditStatus " + name);
  } // method forName

}
