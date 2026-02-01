// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.xipki.security.cmp.CmpUtil;
import org.xipki.security.cmp.PkiStatusInfo;

/**
 * Exception that wraps the PKIStatusInfo.
 *
 * @author Lijun Liao (xipki)
 */

public class PkiErrorException extends Exception {

  private final int status;

  private final int pkiFailureInfo;

  private final String statusMessage;

  public PkiErrorException(PKIStatusInfo statusInfo) {
    this(new PkiStatusInfo(statusInfo));
  }

  public PkiErrorException(PkiStatusInfo statusInfo) {
    this(statusInfo.status(), statusInfo.pkiFailureInfo(),
        statusInfo.statusMessage());
  }

  public PkiErrorException(
      int status, int pkiFailureInfo, String statusMessage) {
    super(CmpUtil.formatPkiStatusInfo(status, pkiFailureInfo, statusMessage));
    this.status = status;
    this.pkiFailureInfo = pkiFailureInfo;
    this.statusMessage = statusMessage;
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

}
