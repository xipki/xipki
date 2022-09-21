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

package org.xipki.cmp.client;

import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.xipki.cmp.PkiStatusInfo;
import org.xipki.cmp.CmpFailureUtil;

/**
 * Exception that wraps the PKIStatusInfo.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class PkiErrorException extends Exception {

  private final int status;

  private final int pkiFailureInfo;

  private final String statusMessage;

  public PkiErrorException(PKIStatusInfo statusInfo) {
    this(new PkiStatusInfo(statusInfo));
  }

  public PkiErrorException(PkiStatusInfo statusInfo) {
    this(statusInfo.status(), statusInfo.pkiFailureInfo(), statusInfo.statusMessage());
  }

  public PkiErrorException(int status, int pkiFailureInfo, String statusMessage) {
    super(CmpFailureUtil.formatPkiStatusInfo(status, pkiFailureInfo, statusMessage));
    this.status = status;
    this.pkiFailureInfo = pkiFailureInfo;
    this.statusMessage = statusMessage;
  }

  public int getStatus() {
    return status;
  }

  public int getPkiFailureInfo() {
    return pkiFailureInfo;
  }

  public String getStatusMessage() {
    return statusMessage;
  }

}
