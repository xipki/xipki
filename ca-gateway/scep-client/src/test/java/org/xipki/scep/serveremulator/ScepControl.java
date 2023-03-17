// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

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

  public ScepControl(boolean sendCaCert, boolean pendingCert, boolean sendSignerCert, String secret) {
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
