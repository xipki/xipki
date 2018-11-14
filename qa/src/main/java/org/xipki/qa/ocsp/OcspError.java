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

package org.xipki.qa.ocsp;

import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public enum OcspError {

  malformedRequest(1),
  internalError(2),
  tryLater(3),
  sigRequired(4),
  unauthorized(5);

  private final int status;

  OcspError(int status) {
    this.status = status;
  }

  public int getStatus() {
    return status;
  }

  public static OcspError forName(String name) {
    Args.notNull(name, "name");
    for (OcspError entry : values()) {
      if (entry.name().equals(name)) {
        return entry;
      }
    }

    throw new IllegalArgumentException("unknown OCSP error '" + name + "'");
  }

  public static OcspError forCode(int status) {
    for (OcspError entry : values()) {
      if (entry.status == status) {
        return entry;
      }
    }

    throw new IllegalArgumentException("unknown OCSP error code '" + status + "'");
  }

}
