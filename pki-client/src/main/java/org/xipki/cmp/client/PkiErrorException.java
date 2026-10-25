// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.xipki.pkix.asn1.cmp.PKIFailureInfo;
import org.xipki.pkix.asn1.cmp.PKIStatus;
import org.xipki.pkix.asn1.cmp.PKIStatusInfo;
import org.xipki.pkix.cmp.CmpUtil;
import org.xipki.pkix.cmp.PkiStatusInfo;

/**
 * Pki Error Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public class PkiErrorException extends Exception {

  private final PKIStatus status;

  private final PKIFailureInfo pkiFailureInfo;

  private final String statusMessage;

  public PkiErrorException(PKIStatusInfo statusInfo) {
    this(new PkiStatusInfo(statusInfo));
  }

  public PkiErrorException(PkiStatusInfo statusInfo) {
    this(statusInfo.status(), statusInfo.pkiFailureInfo(), statusInfo.statusMessage());
  }

  public PkiErrorException(PKIStatus status, PKIFailureInfo pkiFailureInfo, String statusMessage) {
    super(CmpUtil.formatPkiStatusInfo(status, pkiFailureInfo, statusMessage));
    this.status = status;
    this.pkiFailureInfo = pkiFailureInfo;
    this.statusMessage = statusMessage;
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

}
