// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.cmp;

import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.xipki.util.codec.Args;

/**
 * PKIStatus.
 *
 * @author Lijun Liao (xipki)
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

  public PkiStatusInfo(
      org.bouncycastle.asn1.cmp.PKIStatusInfo bcPkiStatusInfo) {
    this.status = Args.notNull(bcPkiStatusInfo, "bcPkiStatusInfo")
        .getStatus().intValue();
    this.pkiFailureInfo = (bcPkiStatusInfo.getFailInfo() == null) ? 0
        : bcPkiStatusInfo.getFailInfo().intValue();

    PKIFreeText text = bcPkiStatusInfo.getStatusString();
    this.statusMessage = (text == null) ? null
        : text.getStringAtUTF8(0).getString();
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
    return CmpUtil.formatPkiStatusInfo(status, pkiFailureInfo, statusMessage);
  }

}
