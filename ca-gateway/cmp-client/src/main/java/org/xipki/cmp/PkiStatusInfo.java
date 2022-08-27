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

package org.xipki.cmp;

import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.xipki.security.util.CmpFailureUtil;

import static org.xipki.util.Args.notNull;

/**
 * PKIStatus.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PkiStatusInfo {

  private final int status;

  private final int pkiFailureInfo;

  private final String statusMessage;

  public PkiStatusInfo(int status, int pkiFailureInfo, String statusMessage) {
    this.status = status;
    this.pkiFailureInfo = pkiFailureInfo;
    this.statusMessage = statusMessage;
  }

  public PkiStatusInfo(int status) {
    this.status = status;
    this.pkiFailureInfo = 0;
    this.statusMessage = null;
  }

  public PkiStatusInfo(org.bouncycastle.asn1.cmp.PKIStatusInfo bcPkiStatusInfo) {
    notNull(bcPkiStatusInfo, "bcPkiStatusInfo");

    this.status = bcPkiStatusInfo.getStatus().intValue();
    this.pkiFailureInfo = (bcPkiStatusInfo.getFailInfo() == null) ? 0 : bcPkiStatusInfo.getFailInfo().intValue();
    PKIFreeText text = bcPkiStatusInfo.getStatusString();
    this.statusMessage = (text == null) ? null : text.getStringAt(0).getString();
  }

  public int status() {
    return status;
  }

  public int pkiFailureInfo() {
    return pkiFailureInfo;
  }

  public String statusMessage() {
    return statusMessage;
  }

  @Override
  public String toString() {
    return CmpFailureUtil.formatPkiStatusInfo(status, pkiFailureInfo, statusMessage);
  }

}
