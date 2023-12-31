// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp;

import org.xipki.util.Args;

/**
 * Protection verification result with the requestor.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ProtectionVerificationResult {

  private final Object requestor;

  private final ProtectionResult protectionResult;

  public ProtectionVerificationResult(Object requestor, ProtectionResult protectionResult) {
    this.requestor = requestor;
    this.protectionResult = Args.notNull(protectionResult, "protectionResult");
  }

  public Object getRequestor() {
    return requestor;
  }

  public ProtectionResult getProtectionResult() {
    return protectionResult;
  }

}
