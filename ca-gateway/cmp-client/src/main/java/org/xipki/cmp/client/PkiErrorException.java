// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.xipki.cmp.CmpFailureUtil;
import org.xipki.cmp.PkiStatusInfo;

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
