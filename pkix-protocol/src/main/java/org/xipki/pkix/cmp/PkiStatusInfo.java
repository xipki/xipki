// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cmp;

import org.xipki.pkix.asn1.cmp.PKIFailureInfo;
import org.xipki.pkix.asn1.cmp.PKIFreeText;
import org.xipki.pkix.asn1.cmp.PKIStatus;
import org.xipki.pkix.asn1.cmp.PKIStatusInfo;
import org.xipki.codec.util.Args;

/**
 * Pki Status information.
 *
 * @author Lijun Liao (xipki)
 */
public class PkiStatusInfo {

  private final PKIStatus status;

  private final PKIFailureInfo pkiFailureInfo;

  private final String statusMessage;

  public PkiStatusInfo(PKIStatus status, PKIFailureInfo pkiFailureInfo, String statusMessage) {
    this.status = status;
    this.pkiFailureInfo = pkiFailureInfo;
    this.statusMessage = statusMessage;
  }

  public PkiStatusInfo(PKIStatus status) {
    this.status = status;
    this.pkiFailureInfo = null;
    this.statusMessage = null;
  }

  public PkiStatusInfo(PKIStatusInfo bcPkiStatusInfo) {
    this.status = Args.notNull(bcPkiStatusInfo, "bcPkiStatusInfo").getStatus();
    this.pkiFailureInfo = bcPkiStatusInfo.getFailInfo();

    PKIFreeText text = bcPkiStatusInfo.getStatusString();
    this.statusMessage = (text == null) ? null : text.getStringAt(0);
  }

  public PKIStatus status() {
    return status;
  }

  public PKIFailureInfo pkiFailureInfo() {
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
