// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cmp;

import org.xipki.pkix.asn1.cmp.PKIMessage;
import org.xipki.codec.util.Args;

/**
 * Verified Pki Message.
 *
 * @author Lijun Liao (xipki)
 */
public class VerifiedPkiMessage {

  private final PKIMessage pkiMessage;

  private ProtectionVerificationResult protectionVerificationResult;

  public VerifiedPkiMessage(PKIMessage pkiMessage) {
    this.pkiMessage = Args.notNull(pkiMessage,"pkiMessage");
  }

  public boolean hasProtection() {
    return pkiMessage.hasProtection();
  }

  public PKIMessage pkiMessage() {
    return pkiMessage;
  }

  public ProtectionVerificationResult protectionVerificationResult() {
    return protectionVerificationResult;
  }

  public void setProtectionVerificationResult(
      ProtectionVerificationResult protectionVerificationResult) {
    this.protectionVerificationResult = protectionVerificationResult;
  }

}
