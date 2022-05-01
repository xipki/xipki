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

package org.xipki.scep.serveremulator;

import org.xipki.util.Args;

/**
 * SCEP control.
 *
 * @author Lijun Liao
 */

public class ScepControl {

  private final boolean sendCaCert;

  private final boolean pendingCert;

  private final boolean sendSignerCert;

  private final String secret;

  public ScepControl(boolean sendCaCert, boolean pendingCert, boolean sendSignerCert,
      String secret) {
    this.secret = Args.notBlank(secret, "secret");
    this.sendCaCert = sendCaCert;
    this.pendingCert = pendingCert;
    this.sendSignerCert = sendSignerCert;
  }

  public boolean isSendCaCert() {
    return sendCaCert;
  }

  public boolean isPendingCert() {
    return pendingCert;
  }

  public boolean isSendSignerCert() {
    return sendSignerCert;
  }

  public String getSecret() {
    return secret;
  }

}
