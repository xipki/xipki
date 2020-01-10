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

package org.xipki.security.cmp;

import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.xipki.util.Args;

/**
 * PKI message with verification result.
 *
 * @author Lijun Liao
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

  public void setProtectionVerificationResult(
      ProtectionVerificationResult protectionVerificationResult) {
    this.protectionVerificationResult = protectionVerificationResult;
  }

}
