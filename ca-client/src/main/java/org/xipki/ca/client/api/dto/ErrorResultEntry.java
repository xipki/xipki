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

package org.xipki.ca.client.api.dto;

import org.xipki.security.cmp.PkiStatusInfo;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ErrorResultEntry extends ResultEntry {

  private final PkiStatusInfo statusInfo;

  public ErrorResultEntry(String id, PkiStatusInfo statusInfo) {
    super(id);
    this.statusInfo = ParamUtil.requireNonNull("statusInfo", statusInfo);
  }

  public ErrorResultEntry(String id, int status, int pkiFailureInfo, String statusMessage) {
    super(id);
    this.statusInfo = new PkiStatusInfo(status, pkiFailureInfo, statusMessage);
  }

  public ErrorResultEntry(String id, int status) {
    super(id);
    this.statusInfo = new PkiStatusInfo(status);
  }

  public PkiStatusInfo getStatusInfo() {
    return statusInfo;
  }

}
