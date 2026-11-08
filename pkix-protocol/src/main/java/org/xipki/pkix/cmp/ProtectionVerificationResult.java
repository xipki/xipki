// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cmp;

import org.xipki.codec.util.Args;

/**
 * Protection Verification result.
 *
 * @author Lijun Liao (xipki)
 */
public class ProtectionVerificationResult {

  private final Object requestor;

  private final ProtectionResult protectionResult;

  public ProtectionVerificationResult(Object requestor, ProtectionResult protectionResult) {
    this.requestor = requestor;
    this.protectionResult = Args.notNull(protectionResult, "protectionResult");
  }

  public Object requestor() {
    return requestor;
  }

  public ProtectionResult protectionResult() {
    return protectionResult;
  }

}
