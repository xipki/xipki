// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp;

import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.xipki.util.Args;

/**
 * PKI message with verification result.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class VerifiedPkiMessage {

  private final GeneralPKIMessage pkiMessage;

  private ProtectionVerificationResult protectionVerificationResult;

  public VerifiedPkiMessage(GeneralPKIMessage pkiMessage) {
    this.pkiMessage = Args.notNull(pkiMessage,"pkiMessage");
  }

  public boolean hasProtection() {
    return pkiMessage.hasProtection();
  }

  public GeneralPKIMessage getPkiMessage() {
    return pkiMessage;
  }

  public ProtectionVerificationResult getProtectionVerificationResult() {
    return protectionVerificationResult;
  }

  public void setProtectionVerificationResult(ProtectionVerificationResult protectionVerificationResult) {
    this.protectionVerificationResult = protectionVerificationResult;
  }

}
